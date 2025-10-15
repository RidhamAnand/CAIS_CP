import { useEffect, useState } from "react";

const API_BASE = "/api";

async function apiRequest(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, options);
  if (!response.ok) {
    let message = "Request failed";
    const raw = await response.text();
    try {
      const parsed = JSON.parse(raw);
      message = parsed.detail || parsed.message || raw;
    } catch {
      message = raw || message;
    }
    throw new Error(message);
  }
  const contentType = response.headers.get("content-type");
  if (contentType && contentType.includes("application/json")) {
    return response.json();
  }
  return response.text();
}

function FlowStatus({ provisionInfo, resourceInfo, stegoInfo, extractionInfo }) {
  return (
    <section className="flow-status">
      <h2>End-to-End Progress</h2>
      <div className="grid two">
        <div className={`status-card ${provisionInfo ? "done" : "pending"}`}>
          <h3>1. Provision KEK</h3>
          {provisionInfo ? (
            <p>KEK version {provisionInfo.version} is active. Operator: {provisionInfo.operator}</p>
          ) : (
            <p>Generate the master KEK with an operator password to unlock the workflow.</p>
          )}
        </div>
        <div className={`status-card ${resourceInfo ? "done" : "pending"}`}>
          <h3>2. Secure Your Secret</h3>
          {resourceInfo ? (
            <>
              <p>
                Resource <strong>{resourceInfo.resourceId}</strong> is paired with key <strong>{resourceInfo.keyId}</strong>.
              </p>
              {resourceInfo.metadata?.encrypted_secret_b64 ? (
                <p>A plaintext secret was encrypted with the new DEK.</p>
              ) : (
                <p>No plaintext was attached to this DEK.</p>
              )}
            </>
          ) : (
            <p>Provide the secret text you want to secure; the app will encrypt it with a new DEK.</p>
          )}
        </div>
        <div className={`status-card ${stegoInfo ? "done" : "pending"}`}>
          <h3>3. Share Stego Image</h3>
          {stegoInfo ? (
            <p>
              Wrapped key hidden in <strong>{stegoInfo.filename}</strong>. Share this image with recipients.
            </p>
          ) : (
            <p>Embed the wrapped key into a PNG cover image to distribute it covertly.</p>
          )}
        </div>
        <div className={`status-card ${extractionInfo ? "done" : "pending"}`}>
          <h3>4. Recover & Decrypt</h3>
          {extractionInfo ? (
            <>
              <p>Recovered DEK {extractionInfo.key_id}.</p>
              {extractionInfo.secret ? (
                <p>The original secret was decrypted and is ready to use.</p>
              ) : (
                <p>No stored secret was associated with this metadata.</p>
              )}
            </>
          ) : (
            <p>Recipients upload the stego image to recover the DEK and decrypt the stored secret.</p>
          )}
        </div>
      </div>
    </section>
  );
}

function ProvisionSection({ onComplete }) {
  const [password, setPassword] = useState("");
  const [operator, setOperator] = useState("");
  const [status, setStatus] = useState(null);

  const handleSubmit = async event => {
    event.preventDefault();
    try {
      const payload = { operator, password };
      const result = await apiRequest("/provision", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      setStatus(`KEK provisioned (version ${result.version}).`);
      onComplete({ version: result.version, operator });
      setPassword("");
    } catch (error) {
      setStatus(`Provision failed: ${error.message}`);
    }
  };

  return (
    <section>
      <h2>Phase 0 · Provision KEK</h2>
      <form onSubmit={handleSubmit} className="grid">
        <label>
          Operator
          <input value={operator} onChange={e => setOperator(e.target.value)} required />
        </label>
        <label>
          Password / Passphrase
          <input
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            required
          />
        </label>
        <button type="submit">Provision KEK</button>
      </form>
      {status && <div className="result">{status}</div>}
    </section>
  );
}

function GenerationSection({ enabled, defaultResourceId, onGenerated }) {
  const [resourceId, setResourceId] = useState(defaultResourceId || "");
  const [operator, setOperator] = useState("");
  const [secret, setSecret] = useState("");
  const [result, setResult] = useState(null);

  useEffect(() => {
    if (!resourceId && defaultResourceId) {
      setResourceId(defaultResourceId);
    }
  }, [defaultResourceId]);

  const handleSubmit = async event => {
    event.preventDefault();
    const payload = {
      resource_id: resourceId.trim(),
      operator: operator.trim(),
      secret: secret.trim(),
    };
    try {
      const response = await apiRequest("/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      setResult(response);
      onGenerated({
        resourceId: response.metadata.resource_id,
        keyId: response.key_id,
        metadata: response.metadata,
        secretPreview: secret.trim(),
      });
    } catch (error) {
      setResult({ error: error.message });
    }
  };

  return (
    <section>
      <h2>Phase 1 · Enter Secret & Generate DEK</h2>
      {!enabled && <p className="hint">Provision a KEK first to unlock key generation.</p>}
      <form onSubmit={handleSubmit} className="grid" aria-disabled={!enabled}>
        <label>
          Resource ID
          <input
            value={resourceId}
            onChange={e => setResourceId(e.target.value)}
            placeholder="e.g. file-123"
            required
          />
        </label>
        <label>
          Operator
          <input value={operator} onChange={e => setOperator(e.target.value)} required />
        </label>
        <label>
          Secret To Protect
          <textarea
            rows={4}
            placeholder="Paste the message or data snippet you need to protect."
            value={secret}
            onChange={e => setSecret(e.target.value)}
            required
          />
        </label>
        <button type="submit" disabled={!enabled}>
          Encrypt Secret & Create DEK
        </button>
      </form>
      {result && (
        <div className="result">
          {result.error ? (
            <p>{result.error}</p>
          ) : (
            <>
              <p>
                <strong>Key ID:</strong> {result.key_id}
              </p>
              {result.metadata?.encrypted_secret_b64 && (
                <p>Secret encrypted and stored with the metadata.</p>
              )}
              <pre>{JSON.stringify(result.metadata, null, 2)}</pre>
            </>
          )}
        </div>
      )}
    </section>
  );
}

function EmbedSection({ resourceId: presetResourceId, keyId, onEmbedded }) {
  const [resourceId, setResourceId] = useState(presetResourceId || "");
  const [operator, setOperator] = useState("");
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);

  useEffect(() => {
    if (!resourceId && presetResourceId) {
      setResourceId(presetResourceId);
    }
  }, [presetResourceId]);

  const handleSubmit = async event => {
    event.preventDefault();
    if (!file) {
      setResult({ error: "Select a cover PNG." });
      return;
    }
    const form = new FormData();
    form.append("resource_id", resourceId.trim());
    form.append("operator", operator.trim());
    form.append("cover_image", file);
    try {
      const response = await apiRequest("/embed", {
        method: "POST",
        body: form,
      });
      setResult(response);
      onEmbedded({ filename: response.filename, download_url: response.download_url, resourceId, keyId });
    } catch (error) {
      setResult({ error: error.message });
    }
  };

  return (
    <section>
      <h2>Phase 2 · Embed Wrapped Key Into Image</h2>
      {!resourceId && <p className="hint">Generate a DEK first to auto-fill the resource ID.</p>}
      <form onSubmit={handleSubmit} className="grid">
        <label>
          Resource ID
          <input value={resourceId} onChange={e => setResourceId(e.target.value)} required />
        </label>
        <label>
          Operator
          <input value={operator} onChange={e => setOperator(e.target.value)} required />
        </label>
        <label>
          Cover PNG
          <input type="file" accept="image/png" onChange={e => setFile(e.target.files[0])} required />
        </label>
        <button type="submit">Embed & Create Stego Image</button>
      </form>
      {result && (
        <div className="result">
          {result.error ? (
            <p>{result.error}</p>
          ) : (
            <p>
              Wrapped key hidden inside {result.filename}. Download via {" "}
              <a href={`${API_BASE}${result.download_url}`} target="_blank" rel="noreferrer">
                this link
              </a>{" "}
              and share the PNG with the recipient.
            </p>
          )}
        </div>
      )}
    </section>
  );
}

function ExtractSection({ resourceId: presetResourceId, onExtracted }) {
  const [resourceId, setResourceId] = useState(presetResourceId || "");
  const [operator, setOperator] = useState("");
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);

  useEffect(() => {
    if (!resourceId && presetResourceId) {
      setResourceId(presetResourceId);
    }
  }, [presetResourceId]);

  const handleSubmit = async event => {
    event.preventDefault();
    if (!file) {
      setResult({ error: "Select stego PNG." });
      return;
    }
    const form = new FormData();
    form.append("resource_id", resourceId.trim());
    form.append("operator", operator.trim());
    form.append("stego_image", file);
    try {
      const response = await apiRequest("/extract", {
        method: "POST",
        body: form,
      });
      setResult(response);
      onExtracted(response);
    } catch (error) {
      setResult({ error: error.message });
    }
  };

  return (
    <section>
      <h2>Phase 4 · Recover DEK & Decrypt Secret</h2>
      {!resourceId && <p className="hint">Enter the resource ID used during generation.</p>}
      <form onSubmit={handleSubmit} className="grid">
        <label>
          Resource ID
          <input value={resourceId} onChange={e => setResourceId(e.target.value)} required />
        </label>
        <label>
          Operator
          <input value={operator} onChange={e => setOperator(e.target.value)} required />
        </label>
        <label>
          Stego PNG
          <input type="file" accept="image/png" onChange={e => setFile(e.target.files[0])} required />
        </label>
        <button type="submit">Extract & Decrypt</button>
      </form>
      {result && (
        <div className="result">
          {result.error ? (
            <p>{result.error}</p>
          ) : (
            <>
              <p>
                <strong>Key ID:</strong> {result.key_id}
              </p>
              <p>
                <strong>DEK (hex):</strong> {result.dek_hex}
              </p>
              {result.secret && (
                <p>
                  <strong>Decrypted Secret:</strong> {result.secret}
                </p>
              )}
              <pre>{JSON.stringify(result.metadata, null, 2)}</pre>
            </>
          )}
        </div>
      )}
    </section>
  );
}

function RotateSection({ onComplete }) {
  const [operator, setOperator] = useState("");
  const [result, setResult] = useState(null);

  const handleSubmit = async event => {
    event.preventDefault();
    const form = new FormData();
    form.append("operator", operator.trim());
    try {
      const response = await apiRequest("/rotate", {
        method: "POST",
        body: form,
      });
      setResult(response);
      onComplete();
    } catch (error) {
      setResult({ error: error.message });
    }
  };

  return (
    <section>
      <h2>Phase 5 · Rotate KEK</h2>
      <form onSubmit={handleSubmit} className="grid two">
        <label>
          Operator
          <input value={operator} onChange={e => setOperator(e.target.value)} required />
        </label>
        <button type="submit">Rotate KEK</button>
      </form>
      {result && (
        <div className="result">
          {result.error ? (
            <p>{result.error}</p>
          ) : (
            <p>
              KEK version {result.new_version} active. Updated {result.updated_keys} keys.
            </p>
          )}
        </div>
      )}
    </section>
  );
}

function RecoverySection() {
  const [keyId, setKeyId] = useState("");
  const [result, setResult] = useState(null);

  const handleSubmit = async event => {
    event.preventDefault();
    try {
      const response = await apiRequest(`/recover/${encodeURIComponent(keyId)}`);
      setResult(response);
    } catch (error) {
      setResult({ error: error.message });
    }
  };

  return (
    <section>
      <h2>Phase 6 · Recovery</h2>
      <form onSubmit={handleSubmit} className="grid two">
        <label>
          Key ID
          <input value={keyId} onChange={e => setKeyId(e.target.value)} required />
        </label>
        <button type="submit">Recover</button>
      </form>
      {result && (
        <div className="result">
          {result.error ? (
            <p>{result.error}</p>
          ) : (
            <p>
              <strong>Recovered DEK:</strong> {result.dek_hex}
            </p>
          )}
        </div>
      )}
    </section>
  );
}

function AuditSection({ refreshToken }) {
  const [entries, setEntries] = useState([]);
  const [valid, setValid] = useState(true);

  useEffect(() => {
    async function fetchAudit() {
      try {
        const response = await apiRequest("/audit");
        setEntries(response.entries || []);
        setValid(response.valid);
      } catch (error) {
        setEntries([]);
        setValid(false);
      }
    }
    fetchAudit();
  }, [refreshToken]);

  return (
    <section>
      <h2>Audit Log</h2>
      <div className={`status-indicator ${valid ? "" : "invalid"}`}>
        Chain {valid ? "valid" : "broken"}
      </div>
      <div className="audit-list">
        {entries.length === 0 && <p>No audit entries yet.</p>}
        {entries.map(entry => (
          <div key={`${entry.timestamp}-${entry.hash}`} className="audit-entry">
            <div className="badge">{entry.operation}</div>
            <p>
              <strong>Key:</strong> {entry.key_id}
            </p>
            <p>
              <strong>Operator:</strong> {entry.operator}
            </p>
            <p>
              <strong>Time:</strong> {entry.timestamp}
            </p>
            {entry.details && <pre>{JSON.stringify(entry.details, null, 2)}</pre>}
          </div>
        ))}
      </div>
    </section>
  );
}

export default function App() {
  const [refreshToken, setRefreshToken] = useState(0);
  const [provisionInfo, setProvisionInfo] = useState(null);
  const [resourceInfo, setResourceInfo] = useState(null);
  const [stegoInfo, setStegoInfo] = useState(null);
  const [extractionInfo, setExtractionInfo] = useState(null);

  const bumpRefresh = () => setRefreshToken(prev => prev + 1);

  const handleProvisioned = info => {
    setProvisionInfo(info);
    setResourceInfo(null);
    setStegoInfo(null);
    setExtractionInfo(null);
    bumpRefresh();
  };

  const handleGenerated = info => {
    setResourceInfo(info);
    setStegoInfo(null);
    setExtractionInfo(null);
    bumpRefresh();
  };

  const handleEmbedded = info => {
    setStegoInfo(info);
    bumpRefresh();
  };

  const handleExtracted = info => {
    setExtractionInfo(info);
    bumpRefresh();
  };

  return (
    <main>
      <h1>Steganographic Key Lifecycle</h1>
      <p className="lead">
        Start with the plaintext you need to protect, turn it into a wrapped symmetric key, hide that key in an innocuous PNG, and let recipients recover both the key and the original secret.
      </p>

      <FlowStatus
        provisionInfo={provisionInfo}
        resourceInfo={resourceInfo}
        stegoInfo={stegoInfo}
        extractionInfo={extractionInfo}
      />

      <ProvisionSection onComplete={handleProvisioned} />
      <GenerationSection
        enabled={Boolean(provisionInfo)}
        defaultResourceId={resourceInfo?.resourceId}
        onGenerated={handleGenerated}
      />
      <EmbedSection
        resourceId={resourceInfo?.resourceId}
        keyId={resourceInfo?.keyId}
        onEmbedded={handleEmbedded}
      />
      <ExtractSection resourceId={resourceInfo?.resourceId} onExtracted={handleExtracted} />
      <RotateSection onComplete={bumpRefresh} />
      <RecoverySection />
      <AuditSection refreshToken={refreshToken} />
    </main>
  );
}
