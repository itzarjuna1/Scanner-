import sys
import os
import threading
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from fpdf import FPDF

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
)

# ================= CONFIG =================
BOT_TOKEN = ""

SEC_HEADERS = [
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-XSS-Protection",
]

# 👇 Custom User-Agent (VPS friendly)
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

MAX_PAGES = 50
PROGRESS_STEP = 5
sys.setrecursionlimit(3000)
# =========================================


# ============== STATE HELPERS ==============
def get_state(context):
    if "visited" not in context.user_data:
        context.user_data["visited"] = set()
        context.user_data["results"] = []
    return context.user_data["visited"], context.user_data["results"]


# ============== CORE LOGIC ==============
def analyze_and_extract(url):
    r = requests.get(url, headers=HEADERS, timeout=8)
    soup = BeautifulSoup(r.text, "html.parser")

    data = {
        "url": url,
        "status": r.status_code,
        "https": url.startswith("https"),
        "headers": {h: h in r.headers for h in SEC_HEADERS},
        "login": any(x in url.lower() for x in ["login", "signin"]),
        "admin": any(x in url.lower() for x in ["admin", "dashboard"]),
        "links": [],
    }

    for a in soup.find_all("a", href=True):
        data["links"].append(a["href"])

    return data


def run_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    visited, results = get_state(context)
    target = context.user_data["target"]
    query = update.callback_query

    queue = [target]
    count = 0

    while queue and len(visited) < MAX_PAGES:
        url = queue.pop(0)

        if url in visited:
            continue
        if urlparse(url).netloc != urlparse(target).netloc:
            continue

        visited.add(url)

        try:
            data = analyze_and_extract(url)
            results.append(data)

            for href in data["links"]:
                link = urljoin(url, href).split("#")[0]
                if link not in visited:
                    queue.append(link)

        except:
            continue

        count += 1

        # 🔄 Live progress update
        if count % PROGRESS_STEP == 0:
            context.application.create_task(
                context.bot.edit_message_text(
                    chat_id=update.effective_chat.id,
                    message_id=query.message.message_id,
                    text=f"🔍 Scanning...\n✅ {count} pages done",
                )
            )

    # ✅ Final message
    context.application.create_task(
        context.bot.edit_message_text(
            chat_id=update.effective_chat.id,
            message_id=query.message.message_id,
            text=f"✅ Scan complete\n📄 Pages scanned: {len(results)}",
        )
    )


def make_pdf(context, user_id):
    _, results = get_state(context)
    filename = f"report_{user_id}.pdf"

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Website Security Audit Report", ln=True)
    pdf.ln(6)

    pdf.set_font("Arial", "B", 9)
    headers = ["URL", "Status", "HTTPS", "Hdrs", "Login/Admin", "Risk"]
    widths = [70, 15, 12, 15, 30, 15]

    for h, w in zip(headers, widths):
        pdf.cell(w, 7, h, border=1)
    pdf.ln()

    pdf.set_font("Arial", size=8)

    for r in results:
        headers_score = sum(r["headers"].values())
        risk = "LOW"
        if not r["https"] or r["admin"]:
            risk = "MEDIUM"
        if r["status"] >= 400:
            risk = "HIGH"

        row = [
            r["url"][:60],
            str(r["status"]),
            "YES" if r["https"] else "NO",
            f"{headers_score}/3",
            "YES" if (r["login"] or r["admin"]) else "NO",
            risk,
        ]

        for item, w in zip(row, widths):
            pdf.cell(w, 6, item, border=1)
        pdf.ln()

    pdf.output(filename)
    return filename


# ============== TELEGRAM ==============
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    kb = [
        [InlineKeyboardButton("🎯 Set Target", callback_data="info")],
        [InlineKeyboardButton("🔍 Start Scan", callback_data="scan")],
        [InlineKeyboardButton("📄 Generate PDF", callback_data="pdf")],
    ]
    await update.message.reply_text(
        "🛡 Advanced Website Scanner Bot\n\n"
        "⚠ Scan only websites you own or have permission for.",
        reply_markup=InlineKeyboardMarkup(kb),
    )


async def set_target(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage:\n/target https://example.com")
        return

    context.user_data.clear()
    context.user_data["target"] = context.args[0].rstrip("/")
    await update.message.reply_text(f"🎯 Target set:\n{context.args[0]}")


async def buttons(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()

    if q.data == "info":
        await q.edit_message_text(
            "Use /target https://example.com\nThen click Start Scan"
        )

    elif q.data == "scan":
        if "target" not in context.user_data:
            await q.edit_message_text(
                "❌ Target not set\nUse /target https://example.com"
            )
            return

        await q.edit_message_text("🔍 Scanning started...")
        threading.Thread(
            target=run_scan,
            args=(update, context),
            daemon=True,
        ).start()

    elif q.data == "pdf":
        if "results" not in context.user_data or not context.user_data["results"]:
            await q.edit_message_text("❌ No scan data available")
            return

        user_id = update.effective_user.id
        filename = make_pdf(context, user_id)

        with open(filename, "rb") as doc:
            await q.message.reply_document(doc)

        os.remove(filename)  # 🧹 cleanup


# ============== RUN ==============
app = ApplicationBuilder().token(BOT_TOKEN).build()
app.add_handler(CommandHandler("start", start))
app.add_handler(CommandHandler("target", set_target))
app.add_handler(CallbackQueryHandler(buttons))
app.run_polling()