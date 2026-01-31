# webscanner_bot.py

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from fpdf import FPDF

from telegram import (
    Update, InlineKeyboardButton, InlineKeyboardMarkup
)
from telegram.ext import (
    ApplicationBuilder, CommandHandler,
    CallbackQueryHandler, ContextTypes
)

BOT_TOKEN = "YOUR_BOT_TOKEN"

visited = set()
results = []
VULN_SCAN = True
SEC_HEADERS = ["X-Frame-Options", "Content-Security-Policy", "X-XSS-Protection"]

# ---------- CORE LOGIC ----------

def analyze(url):
    r = requests.get(url, timeout=8)
    return {
        "url": url,
        "status": r.status_code,
        "https": url.startswith("https"),
        "headers": {h: h in r.headers for h in SEC_HEADERS},
        "login": any(x in url.lower() for x in ["login", "signin"]),
        "admin": any(x in url.lower() for x in ["admin", "dashboard"])
    }

def crawl(url, base):
    if url in visited or urlparse(url).netloc != urlparse(base).netloc:
        return
    visited.add(url)

    try:
        data = analyze(url)
        results.append(data)

        soup = BeautifulSoup(requests.get(url).text, "html.parser")
        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"]).split("#")[0]
            crawl(link, base)
    except:
        pass

def make_pdf():
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Website Security Report", ln=True)
    pdf.ln(5)

    pdf.set_font("Arial", size=10)
    for r in results:
        risk = "LOW"
        if not r["https"] or r["admin"]:
            risk = "MEDIUM"
        if r["status"] >= 400:
            risk = "HIGH"

        pdf.multi_cell(0, 6,
            f"URL: {r['url']}\n"
            f"Status: {r['status']}\n"
            f"HTTPS: {r['https']}\n"
            f"Login: {r['login']} | Admin: {r['admin']}\n"
            f"Risk: {risk}\n"
            f"Headers: {r['headers']}\n"
            "-----------------------------"
        )
    pdf.output("report.pdf")

# ---------- TELEGRAM ----------

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    kb = [
        [InlineKeyboardButton("🔍 Start Scan", callback_data="scan")],
        [InlineKeyboardButton("🛡 Vuln Scan ON/OFF", callback_data="toggle")],
        [InlineKeyboardButton("📄 Generate PDF", callback_data="pdf")]
    ]
    await update.message.reply_text(
        "🧠 Advanced Website Scanner\n\n"
        "⚠ Use only on authorized websites",
        reply_markup=InlineKeyboardMarkup(kb)
    )

async def buttons(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global VULN_SCAN, visited, results
    q = update.callback_query
    await q.answer()

    if q.data == "toggle":
        VULN_SCAN = not VULN_SCAN
        await q.edit_message_text(f"Vulnerability Scan: {'ON' if VULN_SCAN else 'OFF'}")

    elif q.data == "scan":
        visited, results = set(), []
        url = context.user_data.get("url")
        if not url:
            await q.edit_message_text("Send URL first using:\n/target https://example.com")
            return
        await q.edit_message_text("🔍 Scanning started...")
        crawl(url, url)
        await q.edit_message_text(f"✅ Scan complete\nPages found: {len(results)}")

    elif q.data == "pdf":
        if not results:
            await q.edit_message_text("❌ No scan data available")
            return
        make_pdf()
        await q.message.reply_document(open("report.pdf", "rb"))

async def target(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data["url"] = context.args[0].rstrip("/")
    await update.message.reply_text(f"🎯 Target set:\n{context.args[0]}")

# ---------- RUN ----------

app = ApplicationBuilder().token(BOT_TOKEN).build()
app.add_handler(CommandHandler("start", start))
app.add_handler(CommandHandler("target", target))
app.add_handler(CallbackQueryHandler(buttons))
app.run_polling()