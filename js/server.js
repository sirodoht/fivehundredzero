const http = require('http');
const { URL } = require('url');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const util = require('util');
const { exec } = require('child_process');
const { CursorAgent } = require('@cursor-ai/january');

const PORT = process.env.PORT || 3000;
const CONTENT_TYPE = { 'Content-Type': 'text/plain; charset=utf-8' };
const GITHUB_REPO = process.env.GITHUB_REPO || 'mataroablog/mataroa';
const GITHUB_BASE_BRANCH = process.env.GITHUB_BASE_BRANCH || 'main';
const GITHUB_API_BASE = 'https://api.github.com';
const USER_AGENT = 'fivehundredzero-node';
const DEFAULT_AGENT_MODEL = process.env.CURSOR_MODEL || 'composer-1';
const DEFAULT_GIT_AUTHOR_NAME = process.env.GIT_AUTHOR_NAME || 'Cursor Agent';
const DEFAULT_GIT_AUTHOR_EMAIL =
  process.env.GIT_AUTHOR_EMAIL || 'cursor-agent@fivehundredzero.com';
const WORKING_COPY_ROOT =
  process.env.WORKING_COPY_DIR || path.join(process.cwd(), '../../500_working_copy');
const execAsync = util.promisify(exec);
const RG_BINARY = path.join(
  __dirname,
  'node_modules',
  '@cursor-ai',
  'january',
  'bin',
  'rg',
);

const ensureRgExecutable = async () => {
  try {
    await fs.promises.access(RG_BINARY, fs.constants.X_OK);
    console.info('rg binary already executable', { binary: RG_BINARY });
    return;
  } catch {
    // fall through and try to chmod
  }
  try {
    await fs.promises.chmod(RG_BINARY, 0o755);
    await fs.promises.access(RG_BINARY, fs.constants.X_OK);
    console.info('Adjusted execute permission for rg binary used by Cursor Agent.');
  } catch (err) {
    console.error('Failed to set execute permission on rg binary', { binary: RG_BINARY, err });
    throw err;
  }
};

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

  const sign = crypto.createSign('RSA-SHA256');
  sign.update(signingInput);
  sign.end();
  const signature = sign.sign(normalizePrivateKey(privateKey), 'base64');

  return `${signingInput}.${signature.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')}`;
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

const gitHasDiff = async dir => {
  try {
    await execAsync('git diff --quiet', { cwd: dir });
    return false;
  } catch {
    return true;
  }
};

const gitCommitAndPush = async ({ dir, branchName, title, token }) => {
  // ensure git identity
  await execAsync(
    `git config user.name "${DEFAULT_GIT_AUTHOR_NAME}" && git config user.email "${DEFAULT_GIT_AUTHOR_EMAIL}"`,
    { cwd: dir },
  );

  // reset to base branch and create branch
  await execAsync(`git checkout ${GITHUB_BASE_BRANCH}`, { cwd: dir });
  await execAsync('git pull --ff-only', { cwd: dir });
  await execAsync(`git checkout -B ${branchName}`, { cwd: dir });

  // stage and commit
  await execAsync('git add -A', { cwd: dir });
  await execAsync(`git commit -m "${title}"`, { cwd: dir });

  // set remote with token and push
  const remoteUrl = `https://x-access-token:${token}@github.com/${GITHUB_REPO}.git`;
  await execAsync(`git remote set-url origin ${remoteUrl}`, { cwd: dir });
  await execAsync(`git push -u origin ${branchName}`, { cwd: dir });
};

const openPr = async ({ branchName, title, body, token }) => {
  const resp = await githubRequest(
      `/repos/${GITHUB_REPO}/pulls`,
      {
        method: 'POST',
        body: {
        title: title.slice(0, 240),
          head: branchName,
          base: GITHUB_BASE_BRANCH,
        body: body.slice(0, 4000),
        },
      },
      token,
    );
  return resp?.html_url;
};

const buildCursorPrompt = (subject, textBody) => {
  const safeBody = typeof textBody === 'string' ? textBody : '';
  const safeSubject = subject || '(no subject)';

  // Explicit override if the email contains a marker line.
  const lines = safeBody.split('\n').map(line => line.trim());
  const markerLine = lines.find(line =>
    /^agent:|^cursor:|^run cursor:/i.test(line),
  );
  if (markerLine) {
    const userPrompt = markerLine
      .replace(/^agent:|^cursor:|^run cursor:/i, '')
      .trim();
    const prompt = [
      `Subject: ${safeSubject}`,
      'Agent request (via marker):',
      userPrompt || '(empty)',
      '',
      'Email body:',
      safeBody || '(empty)',
    ].join('\n');
    console.info('Cursor prompt built from marker line');
    return prompt;
  }

  // Default: treat as production error email; ask the agent to investigate and fix.
  const looksLikeError =
    /internal server error/i.test(safeSubject) ||
    /internal server error/i.test(safeBody) ||
    /error/i.test(safeSubject);
  if (looksLikeError) {
    const prompt = [
      'Production error received via Postmark.',
      `Subject: ${safeSubject}`,
      '',
      'Full email content:',
      safeBody || '(empty)',
      '',
      'Task for agent:',
      '- Identify the root cause of this error in the repository.',
      '- Propose and apply a fix (with tests if appropriate).',
      '- Summarize changes.',
    ].join('\n');
    console.info('Cursor prompt built from error email');
    return prompt;
  }

  // Default: send raw subject/body to agent.
  const prompt = [
    `Subject: ${safeSubject}`,
    '',
    'Email body:',
    safeBody || '(empty)',
  ].join('\n');
  console.info('Cursor prompt built from non-error email');
  return prompt;
};

const ensureWorkingCopyRepo = async () => {
  const repoName = GITHUB_REPO.split('/')[1] || 'repo';
  const repoDir = path.join(WORKING_COPY_ROOT, repoName);
  await fs.promises.mkdir(WORKING_COPY_ROOT, { recursive: true });

  const gitDir = path.join(repoDir, '.git');
  const exists = await fs.promises
    .stat(gitDir)
    .then(() => true)
    .catch(() => false);

  if (!exists) {
    const cloneUrl = `https://github.com/${GITHUB_REPO}.git`;
    console.info(`Cloning ${cloneUrl} into ${repoDir}`);
    await execAsync(`git clone ${cloneUrl} ${repoDir}`, { cwd: WORKING_COPY_ROOT });
  } else {
    try {
      console.info('Resetting and refreshing existing working copy', { repoDir });
      // Hard reset to discard any uncommitted changes from previous runs
      await execAsync('git reset --hard', { cwd: repoDir });
      // Remove untracked files and directories
      await execAsync('git clean -fd', { cwd: repoDir });
      await execAsync('git fetch --all --prune', { cwd: repoDir });
      await execAsync(`git checkout ${GITHUB_BASE_BRANCH}`, { cwd: repoDir });
      // Reset again to match remote in case of divergence
      await execAsync(`git reset --hard origin/${GITHUB_BASE_BRANCH}`, { cwd: repoDir });
      console.info('Working copy reset and refreshed', { repoDir });
    } catch (err) {
      console.error('Failed to refresh existing working copy; continuing anyway', err);
    }
  }

  return repoDir;
};

const runCursorAgentPrompt = async (prompt, meta = {}) => {
  const apiKey = process.env.CURSOR_API_KEY;
  if (!apiKey) {
    console.error('Missing CURSOR_API_KEY; cannot spin up Cursor agent.');
    return;
  }

  let workingDir;
  try {
    workingDir = await ensureWorkingCopyRepo();
    console.info('Working copy ready for agent', { workingDir });
  } catch (err) {
    console.error('Failed to prepare working copy', err);
    return;
  }

  try {
    await ensureRgExecutable();
    console.info('rg executable verified for agent');
  } catch (err) {
    console.error('Cannot proceed without executable rg binary', err);
    return;
  }

  console.info('Starting Cursor agent run', {
    model: DEFAULT_AGENT_MODEL,
    workingDir,
    promptPreview: prompt?.slice(0, 200),
    subject: meta.subject,
  });

  const agent = new CursorAgent({
    apiKey,
    model: DEFAULT_AGENT_MODEL,
    workingLocation: {
      type: 'local',
      localDirectory: workingDir,
    },
  });

  try {
    const { conversation } = agent.submit({
      message: prompt,
      onStep: step => {
        try {
          const summary =
            step?.message?.content?.slice?.(0, 160) ||
            step?.toolCall?.name ||
            step?.toolResult?.status ||
            JSON.stringify(step).slice(0, 160);
          console.info('Cursor agent step', {
            type: step?.type,
            summary,
          });
        } catch (logErr) {
          console.error('Failed to log Cursor agent step', logErr);
        }
      },
    });
    await conversation;
    console.info('Cursor agent completed for prompt:', prompt);

    const token = await getGithubToken();
    if (!token) {
      console.error('No GitHub token; skipping PR creation');
      return;
    }

    const hasDiff = await gitHasDiff(workingDir);
    if (!hasDiff) {
      console.info('No changes detected after agent run; skipping PR');
      return;
    }

    const branchName =
      `agent-fix-${Date.now().toString(36)}`.slice(0, 48).replace(/[^a-z0-9-]/gi, '-');
    const prTitle = meta.subject
      ? `Agent fix: ${meta.subject}`
      : 'Agent fix from Postmark error';
    const prBody = [
      'Generated by Cursor agent in response to Postmark webhook.',
      '',
      'Prompt:',
      prompt.slice(0, 4000),
    ].join('\n');

    try {
      await gitCommitAndPush({
        dir: workingDir,
        branchName,
        title: prTitle,
        token,
      });
    } catch (err) {
      console.error('Failed to commit/push changes', err);
      return;
    }

    try {
      const prUrl = await openPr({
        branchName,
        title: prTitle,
        body: prBody,
        token,
      });
      console.info('Opened PR from agent changes', { prUrl });
    } catch (err) {
      console.error('Failed to open PR', err);
    }
  } catch (err) {
    console.error('Cursor agent failed', err);
  }
};

const handlePostmark = async (req, res) => {
  console.info('Handling Postmark webhook request');
  let payload;
  try {
    payload = await readJsonBody(req);
  } catch (err) {
    console.error('Failed to parse Postmark webhook', err);
    send(res, 400, 'Invalid payload');
    return;
  }

  // Respond immediately to Postmark.
  send(res, 200, 'ok');

  // Continue processing asynchronously.
  (async () => {
    try {
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
        console.info('Skipping spam webhook');
      return;
    }

      const agentPrompt = buildCursorPrompt(payload.Subject, payload.TextBody);
      console.info('Agent prompt settings:', { subject: payload.Subject, hasPrompt: Boolean(agentPrompt) });
      if (agentPrompt) {
        console.info('Dispatching Cursor agent for webhook');
        await runCursorAgentPrompt(agentPrompt, {
      subject: payload.Subject,
          from: payload.From,
          to: payload.To,
    });
      } else {
        console.info('No agent prompt generated; skipping agent run');
      }
  } catch (err) {
      console.error('Postmark webhook async processing failed', err);
  }
  })();
};

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const path = url.pathname.endsWith('/')
    ? url.pathname.slice(0, -1) || '/'
    : url.pathname;

  console.info('Incoming request', { method: req.method, path });

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
  console.log(`fivehundredzero server listening on http://localhost:${PORT}`);
});
