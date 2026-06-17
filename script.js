// ---- NAVBAR SCROLL ----

window.addEventListener('scroll', function () {
  const navbar = document.querySelector('.navbar');
  const hero = document.getElementById('hero');
  if (window.scrollY > hero.offsetHeight - 80) {
    navbar.classList.add('scrolled');
  } else {
    navbar.classList.remove('scrolled');
  }
});

// ---- EML UPLOAD ----

document.getElementById("emlUpload").addEventListener("change", async function () {
  const file = this.files[0];
  if (!file) return;

  const status = document.getElementById("uploadStatus");
  status.textContent = "Parsing...";

  const formData = new FormData();
  formData.append("file", file);

  try {
    const response = await fetch("/parse-eml", {
      method: "POST",
      body: formData
    });
    const data = await response.json();

    document.getElementById("sender").value   = data.sender   || '';
    document.getElementById("reply_to").value = data.reply_to || '';
    document.getElementById("subject").value  = data.subject  || '';
    document.getElementById("body").value     = data.body     || '';

    status.textContent = `✓ "${file.name}" loaded`;
    status.style.color = "#2dc653";
  } catch (err) {
    status.textContent = "Failed — is the backend running?";
    status.style.color = "#e63946";
  }
});


// ---- ANALYZE ----

document.getElementById("analyzeBtn").addEventListener("click", async function () {
  const sender   = document.getElementById("sender").value.trim();
  const reply_to = document.getElementById("reply_to").value.trim();
  const subject  = document.getElementById("subject").value.trim();
  const body     = document.getElementById("body").value.trim();

  if (!subject && !body) {
    alert("Please enter at least a subject or email body.");
    return;
  }

  const btn = document.getElementById("analyzeBtn");
  btn.disabled = true;
  btn.innerHTML = "<span>⏳</span> Analyzing...";

  try {
    const response = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sender, reply_to, subject, body })
    });

    const result = await response.json();
    displayResult(result.score, result.verdict, result.flags, result.breakdown);

  } catch (error) {
    alert("Could not connect to the backend. Make sure app.py is running.");
    console.error(error);
  } finally {
    btn.disabled = false;
    btn.innerHTML = "<span>🔍</span> Analyze Email";
  }
});


// ---- DISPLAY RESULT ----

function displayResult(score, verdict, flags, breakdown) {

  const verdictConfig = {
    safe:       { label: "Looks Safe",        icon: "✅", color: "#2dc653", border: "#2dc653" },
    suspicious: { label: "Suspicious",         icon: "⚠️", color: "#f4a01a", border: "#f4a01a" },
    phishing:   { label: "Phishing Detected",  icon: "🚨", color: "#e63946", border: "#e63946" }
  };

  const layerColors = {
    "Header":     "#2563eb",
    "Heuristics": "#f4a01a",
    "URL":        "#e63946",
    "ML Model":   "#7c3aed"
  };

  const layerBarColors = {
    header:     "#2563eb",
    heuristics: "#f4a01a",
    url:        "#e63946",
    ml:         "#7c3aed"
  };

  const layerNames = {
    header:     "Header",
    heuristics: "Heuristics",
    url:        "URL",
    ml:         "ML Model"
  };

  const sevColors = {
    high:   "#e63946",
    medium: "#f4a01a",
    low:    "#2dc653"
  };

  const cfg = verdictConfig[verdict];

  // Show result card
  const card = document.getElementById("resultCard");
  card.style.display = "block";
  card.style.borderTopColor = cfg.border;
  card.scrollIntoView({ behavior: "smooth", block: "start" });

  // Verdict box
  document.getElementById("verdictIcon").textContent  = cfg.icon;
  document.getElementById("verdictLabel").textContent = cfg.label;
  document.getElementById("verdictLabel").style.color = cfg.color;
  document.getElementById("verdictScore").innerHTML   = `Risk score: <strong>${score}/100</strong>`;

  // Gauge animation
  const gaugeFill = document.getElementById("gaugeFill");
  const gaugeLabel = document.getElementById("gaugeLabel");
  const totalLength = 157;
  const offset = totalLength - (score / 100) * totalLength;
  gaugeFill.style.stroke = cfg.color;
  gaugeFill.style.strokeDashoffset = offset;
  gaugeLabel.textContent = score;

  // Breakdown
  const breakdownGrid = document.getElementById("breakdownGrid");
  breakdownGrid.innerHTML = Object.entries(breakdown).map(([key, val]) => `
    <div class="breakdown-item">
      <div class="breakdown-label">${layerNames[key] || key}</div>
      <div class="breakdown-bar-wrap">
        <div class="breakdown-bar" style="width:${Math.min(val, 100)}%; background:${layerBarColors[key] || '#888'}"></div>
      </div>
      <div class="breakdown-score">${val}</div>
    </div>
  `).join("");

  // Flags
  document.getElementById("flagsTitle").textContent = `Red Flags Found (${flags.length})`;
  const flagsList = document.getElementById("flagsList");
  flagsList.innerHTML = flags.length === 0
    ? "<p style='color:#bbb;font-size:0.85rem;padding:8px 0'>No red flags found.</p>"
    : flags.map(f => `
        <div class="flag ${f.severity}">
          <span class="flag-dot" style="background:${sevColors[f.severity]}"></span>
          <span class="flag-layer" style="background:${layerColors[f.layer] || '#888'}">${f.layer}</span>
          <span>${f.text}</span>
        </div>
      `).join("");
}
