with open('secret_scanner/api/templates/index.html', 'rb') as f:
    content = f.read()

# Find the position where we need to insert the URL scan function
idx = content.find(b'Git scan error')
if idx >= 0:
    # Find the end of the runGitScan function (the COMMENT line after it)
    idx2 = content.find(b'COMMIT FINDINGS', idx)
    if idx2 >= 0:
        new_func = b'''

/* ============================================================
   SCAN -- URL / WEBSITE
============================================================ */
async function runUrlScan() {
  const url = document.getElementById('url-input').value.trim();
  if (!url) { toast('Enter a URL first.', 'warn'); return; }
  if (!/^https?:\\/\\//i.test(url)) { toast('URL must start with http:// or https://', 'warn'); return; }

  const maxSizeMb = parseInt(document.getElementById('url-max-size').value || '5', 10);
  const followRedirects = document.getElementById('url-follow-redirects').checked;
  const includeSubresources = document.getElementById('url-include-subresources').checked;

  lastTarget  = 'URL: ' + url;
  setBtn('btn-url', true);
  showProgress('prog-url');
  document.getElementById('prog-url-txt').textContent = 'Fetching website...';

  try {
    const payload = { url, follow_redirects: followRedirects, max_size_mb: maxSizeMb };
    const res  = await fetch('/scan/url', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'URL scan failed');

    commitFindings(data.findings, lastTarget, 'fa-globe', 'rgba(34,211,238,.15)');
  } catch(e) { toast('URL scan error: ' + e.message, 'error'); }
  finally { setBtn('btn-url', false); hideProgress('prog-url'); }
}

/* ============================================================
   COMMIT FINDINGS
============================================================ */

'''
        new_content = content[:idx2] + new_func + content[idx2:]
        with open('secret_scanner/api/templates/index.html', 'wb') as f:
            f.write(new_content)
        print('Done - inserted URL scan function')
    else:
        print('Could not find COMMIT FINDINGS')
else:
    print('Could not find Git scan error')