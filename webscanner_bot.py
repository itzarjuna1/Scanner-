import sys
import os
import threading
import asyncio
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


# ============== PDF SAFETY ==============
def pdf_safe(text, max_len=80):
    if not isinstance(text, str):
        text = str(text)
    text = text[:max_len]
    return text.encode("latin-1", "ignore").decode("latin-1")


# ============== ASYNC HELPERS ==============
async def edit_progress(bot, chat_id, msg_id, text):
    try:
        await bot.edit_message_text(
            chat_id=chat_id,
            message_id=msg_id,
            text=text
        )
    except:
        pass


async def store_results(context, results):
    context.user_data["results"] = results
    context.user_data["results_ready"] = True


# ============== CORE LOGIC ==============
def analyze_and_extract(url):
    r = requests.get(url, headers=HEADERS, timeout=8, stream=True)

    content_type = r.headers.get("Content-Type", "")
    if "text/html" not in content_type:
        r.close()
        raise Exception("Non-HTML content skipped")

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


# 🔴 NOTICE: loop is PASSED IN, not fetched
def run_scan(update: Update, context: ContextTypes.DEFAULT_TYPE, loop):
    target = context.user_data["target"]
    query = update.callback_query

    visited = set()
    results = []
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
                if link not in visited and link not in queue:
                    queue.append(link)
        except:
            continue

        count += 1

        if count % PROGRESS_STEP == 0:
            asyncio.run_coroutine_threadsafe(
                edit_progress(
                    context.bot,
                    update.effective_chat.id,
                    query.message.message_id,
                    f"🔍 Scanning… {count} pages done",
                ),
                loop,
            )

    asyncio.run_coroutine_threadsafe(
        store_results(context, results),
        loop,
    )

    asyncio.run_coroutine_threadsafe(
        edit_progress(
            context.bot,
            update.effective_chat.id,
            query.message.message_id,
            f"✅ Scan complete\n📄 Pages scanned: {len(results)}",
        ),
        loop,
    )


def make_pdf(results, user_id):
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
            pdf_safe(r["url"]),
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
    context.user_data["results_ready"] = False
    await update.message.reply_text(f"🎯 Target set:\n{context.args[0]}")


async def buttons(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()

    if q.data == "scan":
        if "target" not in context.user_data:
            await q.edit_message_text("❌ Set target first using /target")
            return

        await q.edit_message_text("🔍 Scanning started…")

        loop = asyncio.get_running_loop()  # ✅ REAL LOOP

        threading.Thread(
            target=run_scan,
            args=(update, context, loop),
            daemon=True,
        ).start()

    elif q.data == "pdf":
        if not context.user_data.get("results_ready"):
            await q.edit_message_text("❌ Scan not completed yet")
            return

        results = context.user_data.get("results", [])
        if not results:
            await q.edit_message_text("❌ No pages were successfully scanned.")
            return

        filename = make_pdf(results, update.effective_user.id)

        with open(filename, "rb") as doc:
            await q.message.reply_document(doc)

        os.remove(filename)


# ============== RUN ==============
app = ApplicationBuilder().token(BOT_TOKEN).build()
app.add_handler(CommandHandler("start", start))
app.add_handler(CommandHandler("target", set_target))
app.add_handler(CallbackQueryHandler(buttons))
app.run_polling()