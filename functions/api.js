// ================== 🔒 绝对安全版（密钥全部从 Cloudflare 后台读取） ==================

// ================== 【1. GET 请求：载入时提示】 ==================
export async function onRequestGet(context) {
  const { request, env } = context;

  // 验证网页端传过来的密码（从 CF 环境变量 env.WEB_PASSWORD 读取）
  const authHeader = request.headers.get("Authorization");
  if (!authHeader) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
  
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
  if (token !== env.WEB_PASSWORD) return new Response(JSON.stringify({ error: "访问密码错误，请刷新页面重新输入。" }), { status: 401 });

  try {
    return new Response(JSON.stringify({ value: "请在此处输入最新的股票代码列表（多个用英文逗号隔开），保存后将直接覆盖云端变量。" }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
}

// ================== 【2. POST 请求：加密并同步至 GitHub】 ==================
export async function onRequestPost(context) {
  const { request, env } = context;

  // 验证网页端传过来的密码
  const authHeader = request.headers.get("Authorization");
  if (!authHeader) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
  
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
  if (token !== env.WEB_PASSWORD) return new Response(JSON.stringify({ error: "访问密码错误，请刷新页面重新输入。" }), { status: 401 });

  try {
    const body = await request.json();
    const stockListText = body.value;

    if (!stockListText) {
      return new Response(JSON.stringify({ error: "股票列表不能为空" }), { status: 400 });
    }

    // A. 抓取 GitHub 仓库的加密公钥（变量全部从 env 中安全读取）
    const publicKeyRes = await fetch(`https://github.com{env.OWNER}/${env.REPO}/actions/secrets/public-key`, {
      headers: {
        "Authorization": `token ${env.GITHUB_TOKEN}`,
        "User-Agent": "Cloudflare-Pages",
        "Accept": "application/vnd.github+json"
      }
    });
        
    if (!publicKeyRes.ok) {
      const errText = await publicKeyRes.text();
      return new Response(JSON.stringify({ error: `无法获取 GitHub 公钥: ${errText}` }), { status: 500 });
    }
    
    const { key_id, key } = await publicKeyRes.json();

    // B. 转换算法：将股票代码进行 libsodium 密封箱加密
    const encryptedValue = await githubSecretEncrypt(stockListText, key);

    // C. 将密文推送到 GitHub Secrets 对应的变量名中
    const githubApiUrl = `https://github.com{env.OWNER}/${env.REPO}/actions/secrets/${env.VAR_NAME}`;
    const putSecretRes = await fetch(githubApiUrl, {
      method: "PUT",
      headers: {
        "Authorization": `token ${env.GITHUB_TOKEN}`,
        "User-Agent": "Cloudflare-Pages",
        "Content-Type": "application/json",
        "Accept": "application/vnd.github+json"
      },
      body: JSON.stringify({
        encrypted_value: encryptedValue,
        key_id: key_id
      })
    });

    if (putSecretRes.ok || putSecretRes.status === 201 || putSecretRes.status === 204) {
      return new Response(JSON.stringify({ success: true }), { status: 200 });
    } else {
      const errText = await putSecretRes.text();
      return new Response(JSON.stringify({ error: `GitHub API 错误: ${errText}` }), { status: 500 });
    }

  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
}

// ================== 【3. GitHub 要求的内置加密引擎】 ==================
async function githubSecretEncrypt(secret, publicKeyBase64) {
  const b64ToUint8 = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const bufToB64 = (buf) => btoa(String.fromCharCode(...buf));
  
  const tweetnacl = await import('https://esm.sh');
  
  const secretUint8 = new TextEncoder().encode(secret);
  const pubKeyUint8 = b64ToUint8(publicKeyBase64);
  
  const ephemeralKeyPair = tweetnacl.box.keyPair();
  const nonce = new Uint8Array(24);
  const encrypted = tweetnacl.box(secretUint8, nonce, pubKeyUint8, ephemeralKeyPair.secretKey);
  
  const sealedBox = new Uint8Array(ephemeralKeyPair.publicKey.length + encrypted.length);
  sealedBox.set(ephemeralKeyPair.publicKey);
  sealedBox.set(encrypted, ephemeralKeyPair.publicKey.length);
  
  return bufToB64(sealedBox);
}
