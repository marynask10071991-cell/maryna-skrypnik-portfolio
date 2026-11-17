import os,base64,hmac,time
from flask import Flask,request,redirect,session,Response
app=Flask(__name__)
app.secret_key=os.environ["APP_SESSION_SECRET"]
app.config.update(SESSION_COOKIE_SECURE=True,SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE="Lax",PERMANENT_SESSION_LIFETIME=1209600)
attempts={}
@app.after_request
def secure(r):
 r.headers["Cache-Control"]="private, no-store"
 r.headers["X-Content-Type-Options"]="nosniff"
 r.headers["X-Frame-Options"]="DENY"
 r.headers["Referrer-Policy"]="no-referrer"
 return r
@app.route("/login",methods=["GET","POST"])
def login():
 ip=request.remote_addr or "unknown"
 now=time.monotonic()
 a=[x for x in attempts.get(ip,[]) if now-x<600];attempts[ip]=a
 error=""
 if request.method=="POST":
  if len(a)>=10:error="Слишком много попыток. Попробуй позже."
  elif hmac.compare_digest(request.form.get("password",""),os.environ["APP_PASSWORD"]):
   session.clear();session.permanent=True;session["auth"]=True;return redirect("/")
  else:attempts[ip].append(now);error="Неверный пароль"
 return Response("""<!doctype html><html lang="ru"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Мои намерения — вход</title><style>body{background:#faf4f7;color:#4b3944;font:16px -apple-system,BlinkMacSystemFont,Arial,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0}main{width:min(80vw,350px);padding:28px;background:white;border-radius:23px;box-shadow:0 8px 28px #b17a961b}h1{font-size:26px}p{color:#7d6a79;line-height:1.5;font-size:14px}input,button{width:100%;box-sizing:border-box;padding:15px;font:inherit;border-radius:12px}input{border:1px solid #dbc4d1;margin:12px 0}button{background:#935b7e;color:white;border:0;font-weight:bold}</style></head><body><main><div style="font-size:40px">✿</div><h1>Мои намерения</h1><p>Личное приложение. Введи пароль, чтобы продолжить.</p><form method="POST"><input type="password" name="password" placeholder="Пароль" autocomplete="current-password" required><button>Открыть</button></form><p style="color:#a53654">"""+error+"""</p></main></body></html>""",mimetype="text/html")
@app.route("/")
@app.route("/index.html")
def main():
 if not session.get("auth"):return redirect("/login")
 return Response(base64.b64decode(os.environ["APP_HTML_B64"]).decode("utf-8"),mimetype="text/html")
@app.route("/logout")
def logout():
 session.clear();return redirect("/login")
@app.route("/manifest.webmanifest")
def manifest():
 if not session.get("auth"):return ("Unauthorized",401)
 return Response('{"name":"Мои намерения","short_name":"Намерения","display":"standalone","start_url":"/","background_color":"#fcf9fa","theme_color":"#f6e7ed"}',mimetype="application/manifest+json")
