# Sensitive member-name rule shared by the AWS adapter (policy/sensitive-names.json documents it; the Python
# engine, the Azure adapter and the Conftest policy implement the same rule). $v is .sensitive_names of that file.
def key_words:
  gsub("(?<a>[a-z0-9])(?<b>[A-Z])"; "\(.a)_\(.b)")
  | gsub("(?<a>[A-Z]+)(?<b>[A-Z][a-z])"; "\(.a)_\(.b)")
  | gsub("(?<a>[A-Za-z])(?<b>[0-9])"; "\(.a)_\(.b)")
  | ascii_downcase
  | [splits("[^a-z0-9]+") | select(length > 0 and (test("^[0-9]+$") | not))];

def sensitive_name($v):
  if type != "string" then false
  else key_words as $w
    | ($w | length) > 0
      and (($w[-1] | IN($v.words[])) or (($w | length) > 1 and ("\($w[-2])_\($w[-1])" | IN($v.pairs[]))))
  end;
