const http = require('http');
const { URL } = require('url');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const CONTENT_TYPE = { 'Content-Type': 'text/plain; charset=utf-8' };
const GITHUB_REPO = process.env.GITHUB_REPO || 'sirodoht/fivehundredzero';
const GITHUB_BASE_BRANCH = process.env.GITHUB_BASE_BRANCH || 'main';
const GITHUB_API_BASE = 'https://api.github.com';
const USER_AGENT = 'fivehundredzero-node';

const send = (res, status, body = '') => {
  res.writeHead(status, CONTENT_TYPE);
  res.end(body);
};

const readJsonBody = (req, maxBytes = 1_000_000) =>
  new Promise((resolve, reject) => {
    let data = '';

    req.on('data', chunk => {
      data += chunk;
      if (data.length > maxBytes) {
        reject(new Error('Payload too large'));
        req.destroy();
      }
    });

    req.on('end', () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch (err) {
        reject(err);
      }
    });

    req.on('error', reject);
  });

const findHeader = (headers, name) =>
  headers.find(
    header =>
      typeof header?.Name === 'string' &&
      header.Name.toLowerCase() === name.toLowerCase(),
  );

const base64Url = input =>
  Buffer.from(input)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

const normalizePrivateKey = key => key.replace(/\\n/g, '\n');

const signGithubAppJwt = (appId, privateKey) => {
  const header = { alg: 'RS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iat: now - 60,
    exp: now + 9 * 60,
    iss: appId,
  };

  const signingInput = `${base64Url(JSON.stringify(header))}.${base64Url(
    JSON.stringify(payload),
  )}`;

  const signature = crypto.sign('RSA-SHA256', Buffer.from(signingInput), {
    key: normalizePrivateKey(privateKey),
    padding: crypto.constants.RSA_PKCS1_PADDING,
  });

  return `${signingInput}.${base64Url(signature)}`;
};

const githubRequest = async (path, options, token) => {
  const { body, headers, method = 'GET', ...rest } = options || {};
  const resp = await fetch(`${GITHUB_API_BASE}${path}`, {
    method,
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'User-Agent': USER_AGENT,
      'X-GitHub-Api-Version': '2022-11-28',
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
    ...rest,
  });

  if (!resp.ok) {
    const text = await resp.text();
    const error = new Error(`GitHub API error ${resp.status}`);
    error.status = resp.status;
    error.body = text;
    throw error;
  }

  if (resp.status === 204) return null;

  const contentType = resp.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return resp.json();
  }
  return resp.text();
};

const getInstallationToken = async () => {
  const appId = process.env.GITHUB_APP_ID;
  const installationId = process.env.GITHUB_INSTALLATION_ID;
  const privateKey = process.env.GITHUB_APP_PRIVATE_KEY;

  if (!appId || !installationId || !privateKey) {
    console.error(
      'GitHub App credentials missing; set GITHUB_APP_ID, GITHUB_INSTALLATION_ID, and GITHUB_APP_PRIVATE_KEY.',
    );
    return null;
  }

  let signedJwt;
  try {
    signedJwt = signGithubAppJwt(appId, privateKey);
  } catch (err) {
    console.error('Failed to sign GitHub App JWT', err);
    return null;
  }

  try {
    const resp = await githubRequest(
      `/app/installations/${installationId}/access_tokens`,
      { method: 'POST' },
      signedJwt,
    );
    return resp?.token || null;
  } catch (err) {
    console.error('GitHub App token request failed', {
      status: err.status,
      body: err.body,
      error: err,
    });
    return null;
  }
};

const getGithubToken = async () => {
  if (process.env.GITHUB_TOKEN) {
    return process.env.GITHUB_TOKEN;
  }
  return getInstallationToken();
};

const createPrWithTestFile = async details => {
  const token = await getGithubToken();
  if (!token) {
    console.error('No GitHub token available; cannot open PR.');
    return;
  }

  const branchName =
    `postmark-${crypto.randomUUID?.().replace(/-/g, '').slice(0, 12)}` ||
    `postmark-${crypto.randomBytes(6).toString('hex')}`;

  const bodyContent = `From: ${details.fromEmail}\nTo: ${details.toEmail}\nSubject: ${details.subject}\n\n${details.textBody || ''}\n`;
  const encodedContent = Buffer.from(bodyContent).toString('base64');

  try {
    const ref = await githubRequest(
      `/repos/${GITHUB_REPO}/git/ref/heads/${GITHUB_BASE_BRANCH}`,
      {},
      token,
    );
    const baseSha = ref?.object?.sha;
    if (!baseSha) {
      throw new Error('Missing base branch SHA');
    }

    await githubRequest(
      `/repos/${GITHUB_REPO}/git/refs`,
      {
        method: 'POST',
        body: { ref: `refs/heads/${branchName}`, sha: baseSha },
      },
      token,
    );

    await githubRequest(
      `/repos/${GITHUB_REPO}/contents/test`,
      {
        method: 'PUT',
        body: {
          message: `Add test file from Postmark webhook ${branchName}`,
          content: encodedContent,
          branch: branchName,
        },
      },
      token,
    );

    const prTitle = `Postmark email: ${details.subject || 'No subject'}`.slice(
      0,
      240,
    );
    const prBody = `Auto-created from Postmark webhook.\n\nFrom: ${details.fromEmail}\nTo: ${details.toEmail}\n\n${details.textBody || ''}`.slice(
      0,
      4000,
    );

    const prResp = await githubRequest(
      `/repos/${GITHUB_REPO}/pulls`,
      {
        method: 'POST',
        body: {
          title: prTitle,
          head: branchName,
          base: GITHUB_BASE_BRANCH,
          body: prBody,
        },
      },
      token,
    );

    console.info('Created PR for Postmark email', prResp?.html_url);
  } catch (err) {
    console.error('GitHub API error creating PR', {
      status: err.status,
      body: err.body,
      error: err,
    });
  }
};

const handlePostmark = async (req, res) => {
  try {
    const payload = await readJsonBody(req);

    const headers = Array.isArray(payload.Headers) ? payload.Headers : [];
    const messageIdHeader = findHeader(headers, 'message-id');
    const spamHeader = headers.find(
      header =>
        header?.Name === 'X-Spam-Status' &&
        typeof header.Value === 'string' &&
        header.Value.toLowerCase() === 'yes',
    );

    const spamStatus = Boolean(spamHeader);

    console.info('Postmark webhook payload', {
      from: payload.From,
      to: payload.To,
      subject: payload.Subject,
      spamStatus,
      messageId: messageIdHeader?.Value,
      textBody: payload.TextBody,
      headers,
    });

    if (spamStatus) {
      send(res, 200, 'ok');
      return;
    }

    await createPrWithTestFile({
      fromEmail: payload.From,
      toEmail: payload.To,
      subject: payload.Subject,
      textBody: payload.TextBody,
    });

    send(res, 200, 'ok');
  } catch (err) {
    console.error('Failed to handle Postmark webhook', err);
    send(res, 400, 'Invalid payload');
  }
};

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const path = url.pathname.endsWith('/')
    ? url.pathname.slice(0, -1) || '/'
    : url.pathname;

  if (req.method === 'GET' && path === '/') {
    send(res, 200, 'Hello');
    return;
  }

  if (req.method === 'POST' && (path === '/postmark' || path === '/postmark/')) {
    handlePostmark(req, res);
    return;
  }

  send(res, 404, 'Not found');
});

server.listen(PORT, () => {
  // Log so we can confirm the server is running.
  console.log(`haha server listening on http://localhost:${PORT}`);
});
