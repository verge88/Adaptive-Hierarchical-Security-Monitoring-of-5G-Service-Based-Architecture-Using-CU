"""Download only pinned Stage38 archives; verify their original GitHub digests."""
import hashlib, io, json, os, urllib.request, zipfile
from pathlib import Path
ARTIFACTS = [{"id":11997535178,"sha":"d0a0f90985bdf587f8a7701beb4b841e1f02a23917536fcc9ec9902ca167c4d5","directory":"original_report"},{"id":11996604262,"sha":"4350e8ecc6bf5e7d505c9843e949c3d62714dd0288a71972aba8397d15aec0ca","directory":"evidence"},{"id":11996269786,"sha":"85090fb70e8dbef958beb2f74e1ed91a5bf3bee5e54b614966d76fd9d700fb97","directory":"meta"},{"id":11996179745,"sha":"ae9f2969ede1774b12d28ddb501927d87872e13a184d65c1645dc70852e75371","directory":"labels"}]
class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None:
            redirected.remove_header("Authorization")
        return redirected
opener = urllib.request.build_opener(Redirect())
for item in ARTIFACTS:
    url = "https://api.github.com/repos/verge88/Adaptive-Hierarchical-Security-Monitoring-of-5G-Service-Based-Architecture-Using-CU/actions/artifacts/" + str(item["id"]) + "/zip"
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"], "Accept": "application/vnd.github+json"})
    with opener.open(request, timeout=120) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != item["sha"]:
        raise ValueError("archive hash mismatch: " + str(item["id"]))
    root = (Path("stage38_input") / item["directory"]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for member in archive.infolist():
            if not (root / member.filename).resolve().is_relative_to(root):
                raise ValueError("unsafe archive member")
        archive.extractall(root)
    print("Verified original archive", item["id"], item["sha"])
Path("stage38_input/provenance.json").write_text(json.dumps(ARTIFACTS, indent=2))
