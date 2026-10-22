# Policy Forge AWS adapter: AWS-CLI-shaped JSON exports -> normalized resources (one JSON object per output).
# Inputs: manifest.json, context.json, then the manifest's data files in manifest order (see normalize.sh).
# Properties are an explicit allowlist: raw fields that are not listed here (secrets, user data, environment
# variables, access keys) are never copied. Tags whose key looks sensitive are dropped as well.
# Portable to jq 1.6+.

def sensitive_name: test("passw(or)?d|secret|token|credential|connection_?string|private_?key|account_?key|user_?data|sas_?token"; "i");
def ptr($path): if ($path | length) == 0 then "" else "/" + ($path | map(tostring | gsub("~"; "~0") | gsub("/"; "~1")) | join("/")) end;
def arr: if . == null then [] elif type == "array" then . else [.] end;
def tagmap: (. // []) | map(select((.Key | sensitive_name) | not) | {(.Key): .Value}) | add // {};

def principals:
  if . == null then null
  elif . == "*" then ["*"]
  elif type == "object" then [to_entries[] | .key as $k | (.value | arr[]) | if . == "*" and $k == "AWS" then "*" else "\($k):\(.)" end]
  else ["unparsed:\(tostring)"] end;

def statement($raw):
  if type != "object" then {parse_error: true}
  else {
    sid: (.Sid // null),
    effect: (.Effect // null),
    actions: (if has("Action") then (.Action | arr) else null end),
    not_actions: (if has("NotAction") then (.NotAction | arr) else null end),
    resources: (if has("Resource") then (.Resource | arr) else null end),
    not_resources: (if has("NotResource") then (.NotResource | arr) else null end),
    principals: (.Principal | principals),
    not_principals: (if has("NotPrincipal") then (.NotPrincipal | principals) else null end),
    has_condition: has("Condition"),
    raw: $raw
  } end;

# . is a policy document (object, or a JSON string as get-bucket-policy returns it). $base is the raw
# "file#pointer" of the document; statement pointers are only meaningful when the document is an object.
def permissions($file; $path; $label):
  (type == "string") as $encoded
  | (if $encoded then (try fromjson catch null) else . end) as $d
  | if ($d | type) != "object" or ((($d.Statement | type) == "array" or ($d.Statement | type) == "object") | not) then
      {parse_error: true, statements: []}
    else
      [ ($d.Statement | if type == "array" then to_entries[] else {key: null, value: .} end)
        | (if $encoded then $path elif .key == null then $path + ["Statement"] else $path + ["Statement", .key] end) as $sp
        | .value | statement("\($file)#\(ptr($sp))") | . + {policy: $label} ] as $s
      | {parse_error: ($s | any(.parse_error == true)), statements: [$s[] | select(.parse_error != true)]}
    end;

def merge_permissions: {parse_error: (map(.parse_error) | any), statements: (map(.statements) | add // [])};

def resource($file; $path; $type; $native_type; $native_id; $name; $region; $props; $refs):
  {id: "aws:\($type):\($native_id)", provider: "aws", type: $type, native_type: $native_type, name: $name,
   region: $region, properties: $props, refs: $refs, source: {file: $file, pointer: ptr($path)}};

def unsupported($file; $path; $v; $region):
  ($v | if type == "object" then [to_entries[] | select((.key | test("(Arn|ARN)$")) and (.value | type) == "string")] else [] end) as $arns
  | ($arns[0].value // null) as $arn
  | (if $arn then "AWS::\($arn | split(":")[2])::\($arns[0].key | sub("(Arn|ARN)$"; ""))" else "unknown" end) as $nt
  | ($v | if type == "object" then ([to_entries[] | select((.key | test("Name$")) and (.value | type) == "string") | .value][0] // null) else null end) as $nm
  | resource($file; $path; "unsupported"; $nt; ($arn // $nm // "\($file)#\(ptr($path))"); ($nm // $arn // "unnamed");
             (if $arn then ($arn | split(":")[3] | if . == "" then "global" else . end) else $region end); {}; []);

def proto:
  (tostring | ascii_downcase) as $p
  | if $p == "-1" then "all" elif $p == "tcp" or $p == "6" then "tcp" elif $p == "udp" or $p == "17" then "udp"
    elif $p == "icmp" or $p == "1" then "icmp" elif $p == "icmpv6" or $p == "58" then "icmpv6" else $p end;

def ingress($file; $path):
  (.IpProtocol | proto) as $p
  | {protocol: $p,
     port_from: (if $p == "all" then 0 elif ($p == "tcp" or $p == "udp") then (.FromPort // null) else null end),
     port_to: (if $p == "all" then 65535 elif ($p == "tcp" or $p == "udp") then (.ToPort // null) else null end),
     cidrs: ([(.IpRanges // [])[] | .CidrIp] + [(.Ipv6Ranges // [])[] | .CidrIpv6]),
     source_tags: [],
     source_groups: [(.UserIdGroupPairs // [])[] | "aws:security_group:\(.GroupId)"],
     prefix_lists: [(.PrefixListIds // [])[] | .PrefixListId],
     action: "allow", priority: null, raw: "\($file)#\(ptr($path))"};

(reduce inputs as $doc ({}; .[input_filename | split("/") | last] = $doc)) as $in
| $in["manifest.json"] as $m
| ($in["context.json"] // {}) as $ctx
| ($ctx.default_region // "unknown") as $region
| "snapshots/\($m.name)" as $dir
| ($in["iam-account-authorization-details.json"] // {}) as $iam
| ([($iam.RoleDetailList // [])[] | .Arn as $r | (.InstanceProfileList // [])[] | {key: .Arn, value: $r}] | from_entries) as $profile_role
| $m.files[] as $f
| "\($dir)/\($f)" as $file
| $in[$f] as $doc
| if $f == "s3-buckets.json" then
    ($doc.Buckets // []) | to_entries[] | .key as $i | .value as $b | ["Buckets", $i] as $p
    | ($b.GetPublicAccessBlock.PublicAccessBlockConfiguration // {}) as $pab
    | ($b.GetBucketLogging.LoggingEnabled.TargetBucket // null) as $log_target
    | resource($file; $p; "storage_bucket"; "AWS::S3::Bucket"; $b.Name; $b.Name; ($b.BucketRegion // $region);
        {public_access: {
           anonymous_grants: [($b.GetBucketAcl.Grants // []) | to_entries[]
             | select(.value.Grantee.Type == "Group" and ((.value.Grantee.URI // "") | test("/global/(AllUsers|AuthenticatedUsers)$")))
             | {via: "acl", grantee: (.value.Grantee.URI | split("/") | last), permission: .value.Permission,
                raw: "\($file)#\(ptr($p + ["GetBucketAcl", "Grants", .key]))"}],
           anonymous_grants_blocked: ($pab.IgnorePublicAcls == true),
           policy: (if $b.GetBucketPolicy == null then null
                    else ($b.GetBucketPolicy.Policy | permissions($file; $p + ["GetBucketPolicy", "Policy"]; "bucket-policy")) end),
           public_policy_blocked: ($pab.RestrictPublicBuckets == true),
           guard: {configured: ($b.GetPublicAccessBlock != null), block_public_acls: ($pab.BlockPublicAcls == true),
                   ignore_public_acls: ($pab.IgnorePublicAcls == true), block_public_policy: ($pab.BlockPublicPolicy == true),
                   restrict_public_buckets: ($pab.RestrictPublicBuckets == true)}},
         logging: {enabled: ($log_target != null), target: $log_target},
         tags: ($b.GetBucketTagging.TagSet | tagmap),
         raw: {guard: "\($file)#\(ptr($p + ["GetPublicAccessBlock"]))", policy: "\($file)#\(ptr($p + ["GetBucketPolicy"]))"}};
        (if $log_target then [{kind: "logs_to", target: "aws:storage_bucket:\($log_target)"}] else [] end))
  elif $f == "iam-account-authorization-details.json" then
    (($doc.Policies // []) | to_entries[] | .key as $i | .value as $pol | ["Policies", $i] as $p
      | ([($pol.PolicyVersionList // []) | to_entries[] | select(.value.IsDefaultVersion == true)][0]) as $v
      | resource($file; $p; "iam_policy"; "AWS::IAM::ManagedPolicy"; $pol.Arn; $pol.PolicyName; "global";
          {managed_by: (if ($pol.Arn | startswith("arn:aws:iam::aws:")) then "aws" else "customer" end),
           arn: $pol.Arn, attachment_count: ($pol.AttachmentCount // 0),
           permissions: (if $v == null then {parse_error: true, statements: []}
                         else ($v.value.Document | permissions($file; $p + ["PolicyVersionList", $v.key, "Document"]; $pol.PolicyName)) end)};
          [])),
    (($doc.RoleDetailList // []) | to_entries[] | .key as $i | .value as $r | ["RoleDetailList", $i] as $p
      | resource($file; $p; "iam_role"; "AWS::IAM::Role"; $r.Arn; $r.RoleName; "global";
          {arn: $r.Arn,
           permissions: ([($r.RolePolicyList // []) | to_entries[]
                          | .key as $k | .value.PolicyName as $n | .value.PolicyDocument
                          | permissions($file; $p + ["RolePolicyList", $k, "PolicyDocument"]; "inline:\($n)")] | merge_permissions),
           attached_policy_arns: [($r.AttachedManagedPolicies // [])[] | .PolicyArn],
           instance_profile_arns: [($r.InstanceProfileList // [])[] | .Arn]};
          [($r.AttachedManagedPolicies // [])[] | {kind: "attached_policy", target: "aws:iam_policy:\(.PolicyArn)"}])),
    (($doc.UserDetailList // []) | to_entries[] | .key as $i | .value as $u | ["UserDetailList", $i] as $p
      | resource($file; $p; "iam_user"; "AWS::IAM::User"; $u.Arn; $u.UserName; "global";
          {arn: $u.Arn,
           permissions: ([($u.UserPolicyList // []) | to_entries[]
                          | .key as $k | .value.PolicyName as $n | .value.PolicyDocument
                          | permissions($file; $p + ["UserPolicyList", $k, "PolicyDocument"]; "inline:\($n)")] | merge_permissions),
           attached_policy_arns: [($u.AttachedManagedPolicies // [])[] | .PolicyArn],
           group_names: ($u.GroupList // []),
           raw: {group_names: "\($file)#\(ptr($p + ["GroupList"]))", attached_policy_arns: "\($file)#\(ptr($p + ["AttachedManagedPolicies"]))"}};
          ([($u.AttachedManagedPolicies // [])[] | {kind: "attached_policy", target: "aws:iam_policy:\(.PolicyArn)"}]
           + [($u.GroupList // [])[] | {kind: "member_of", target: "arn:aws:iam::\($ctx.account_id):group/\(.)"}]))),
    (($doc.GroupDetailList // []) | to_entries[] | unsupported($file; ["GroupDetailList", .key]; .value; "global")
      | .native_type = "AWS::IAM::Group")
  elif $f == "ec2-describe-security-groups.json" then
    ($doc.SecurityGroups // []) | to_entries[] | .key as $i | .value as $g | ["SecurityGroups", $i] as $p
    | resource($file; $p; "security_group"; "AWS::EC2::SecurityGroup"; $g.GroupId; ($g.GroupName // $g.GroupId); $region;
        {ingress: [($g.IpPermissions // []) | to_entries[] | .key as $k | .value | ingress($file; $p + ["IpPermissions", $k])],
         vpc_id: ($g.VpcId // null), tags: ($g.Tags | tagmap)};
        [])
  elif $f == "ec2-describe-instances.json" then
    ($doc.Reservations // []) | to_entries[] | .key as $ri | (.value.Instances // []) | to_entries[] | .key as $ii | .value as $x
    | ["Reservations", $ri, "Instances", $ii] as $p
    | ($x.IamInstanceProfile.Arn // null) as $prof
    | resource($file; $p; "compute_instance"; "AWS::EC2::Instance"; $x.InstanceId;
        ([($x.Tags // [])[] | select(.Key == "Name") | .Value][0] // $x.InstanceId);
        (($x.Placement.AvailabilityZone // "") | if . == "" then $region else sub("[a-z]$"; "") end);
        {public_ips: ([$x.PublicIpAddress] | map(select(. != null))),
         network_groups: [($x.SecurityGroups // [])[] | "aws:security_group:\(.GroupId)"],
         instance_profile: $prof,
         state: ($x.State.Name // null),
         tags: ($x.Tags | tagmap),
         raw: {public_ips: "\($file)#\(ptr($p + ["PublicIpAddress"]))", network_groups: "\($file)#\(ptr($p + ["SecurityGroups"]))",
               instance_profile: "\($file)#\(ptr($p + ["IamInstanceProfile"]))"}};
        ([($x.SecurityGroups // [])[] | {kind: "uses_network_group", target: "aws:security_group:\(.GroupId)"}]
         + (if $prof == null then []
            elif $profile_role[$prof] then [{kind: "instance_role", target: "aws:iam_role:\($profile_role[$prof])"}]
            else [{kind: "instance_role", target: $prof}] end)))
  elif $f == "cloudtrail-describe-trails.json" then
    ($in["cloudtrail-get-trail-status.json"].TrailStatus // []) as $status
    | ($doc.trailList // []) | to_entries[] | .key as $i | .value as $t | ["trailList", $i] as $p
    | ([$status | to_entries[] | select(.value.TrailARN == $t.TrailARN or .value.Name == $t.Name)][0]) as $st
    | "\($dir)/cloudtrail-get-trail-status.json" as $sfile
    | resource($file; $p; "audit_trail"; "AWS::CloudTrail::Trail"; $t.TrailARN; $t.Name; ($t.HomeRegion // $region);
        {is_logging: (if $st == null then null else ($st.value.IsLogging == true) end),
         multi_region: ($t.IsMultiRegionTrail == true),
         log_file_validation: ($t.LogFileValidationEnabled == true),
         include_global_service_events: ($t.IncludeGlobalServiceEvents == true),
         organization_trail: ($t.IsOrganizationTrail == true),
         destination: ($t.S3BucketName // null),
         raw: {is_logging: (if $st == null then null else "\($sfile)#\(ptr(["TrailStatus", $st.key, "IsLogging"]))" end),
               multi_region: "\($file)#\(ptr($p + ["IsMultiRegionTrail"]))",
               log_file_validation: "\($file)#\(ptr($p + ["LogFileValidationEnabled"]))",
               destination: "\($file)#\(ptr($p + ["S3BucketName"]))"}};
        (if $t.S3BucketName then [{kind: "delivers_logs_to", target: "aws:storage_bucket:\($t.S3BucketName)"}] else [] end))
  elif $f == "cloudtrail-get-trail-status.json" then
    empty
  elif ($doc | type) == "array" then
    $doc | to_entries[] | unsupported($file; [.key]; .value; $region)
  elif ($doc | type) == "object" then
    $doc | to_entries[] | select(.value | type == "array") | .key as $k | .value | to_entries[]
    | unsupported($file; [$k, .key]; .value; $region)
  else
    empty
  end
