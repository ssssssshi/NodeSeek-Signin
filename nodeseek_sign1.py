# nodeseek_sign.py
# 多账号支持 + 登录成功后自动将 Cookie 持久化到 GitHub Repository Variables

import os
import time
from curl_cffi import requests
from yescaptcha import YesCaptchaSolver, YesCaptchaSolverError

# ---------------- 通知模块动态加载 ----------------
hadsend = False
send = None
try:
    from notify import send
    hadsend = True
except ImportError:
    print("未加载通知模块，跳过通知功能")

# ---------------- GitHub 变量写入函数 ----------------
def save_cookie_to_github_var(var_name: str, cookie: str):
    import requests as py_requests
    token = os.environ.get("GH_PAT")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not token or not repo:
        print("GH_PAT 或 GITHUB_REPOSITORY 未设置，跳过变量更新")
        return

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json"
    }

    url_check = f"https://api.github.com/repos/{repo}/actions/variables/{var_name}"
    url_create = f"https://api.github.com/repos/{repo}/actions/variables"

    data = {"name": var_name, "value": cookie}

    response = py_requests.patch(url_check, headers=headers, json=data)
    if response.status_code == 204:
        print(f"{var_name} 更新成功")
    elif response.status_code == 404:
        print(f"{var_name} 不存在，尝试创建...")
        response = py_requests.post(url_create, headers=headers, json=data)
        if response.status_code == 201:
            print(f"{var_name} 创建成功")
        else:
            print("创建失败:", response.status_code, response.text)
    else:
        print("设置失败:", response.status_code, response.text)

# ---------------- 登录逻辑 ----------------
def session_login(user, password, solver_type, api_base_url, client_key):
    try:
        solver = YesCaptchaSolver(
            api_base_url=api_base_url or "https://api.yescaptcha.com",
            client_key=client_key
        ) if solver_type.lower() == "yescaptcha" else None

        token = solver.solve(
            url="https://www.nodeseek.com/signIn.html",
            sitekey="0x4AAAAAAAaNy7leGjewpVyR",
            verbose=True
        )
        if not token:
            print("验证码解析失败")
            return None
    except Exception as e:
        print(f"验证码错误: {e}")
        return None

    session = requests.Session(impersonate="chrome110")
    session.get("https://www.nodeseek.com/signIn.html")

    data = {
        "username": user,
        "password": password,
        "token": token,
        "source": "turnstile"
    }
    headers = {
        'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
        'sec-ch-ua': "\"Not A(Brand\";v=\"99\", \"Microsoft Edge\";v=\"121\", \"Chromium\";v=\"121\"",
        'sec-ch-ua-mobile': "?0",
        'sec-ch-ua-platform': "\"Windows\"",
        'origin': "https://www.nodeseek.com",
        'sec-fetch-site': "same-origin",
        'sec-fetch-mode': "cors",
        'sec-fetch-dest': "empty",
        'referer': "https://www.nodeseek.com/signIn.html",
        'accept-language': "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        'Content-Type': "application/json"
    }
    try:
        response = session.post("https://www.nodeseek.com/api/account/signIn", json=data, headers=headers)
        resp_json = response.json()
        if resp_json.get("success"):
            cookies = session.cookies.get_dict()
            cookie_string = '; '.join([f"{k}={v}" for k, v in cookies.items()])
            return cookie_string
        else:
            print("登录失败:", resp_json.get("message"))
            return None
    except Exception as e:
        print("登录异常:", e)
        return None

# ---------------- 签到逻辑 ----------------
def sign(ns_cookie, random_value="true"):
    headers = {
        'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
        'origin': "https://www.nodeseek.com",
        'referer': "https://www.nodeseek.com/board",
        'Cookie': ns_cookie
    }
    try:
        url = f"https://www.nodeseek.com/api/attendance?random={random_value}"
        response = requests.post(url, headers=headers, impersonate="chrome110")
        data = response.json()
        msg = data.get("message", "")
        if "鸡腿" in msg or data.get("success"):
            return "success", msg
        elif "已完成签到" in msg:
            return "already", msg
        elif data.get("status") == 404:
            return "invalid", msg
        return "fail", msg
    except Exception as e:
        return "error", str(e)

# ---------------- 主流程 ----------------
if __name__ == "__main__":
    solver_type = os.getenv("SOLVER_TYPE", "yescaptcha")
    api_base_url = os.getenv("API_BASE_URL", "")
    client_key = os.getenv("CLIENTT_KEY", "")

    for i in range(1, 10):
        user = os.getenv(f"USER_{i}")
        password = os.getenv(f"PASS_{i}")
        cookie = os.getenv(f"NS_COOKIE_{i}", "")
        if not user or not password:
            break

        print(f"\n==== 账号 {i} 开始签到 ====")
        result, msg = sign(cookie)

        if result in ["success", "already"]:
            print(f"账号 {i} 签到成功: {msg}")
        else:
            print("尝试重新登录...")
            new_cookie = session_login(user, password, solver_type, api_base_url, client_key)
            if new_cookie:
                print("登录成功，重新签到...")
                result, msg = sign(new_cookie)
                if result in ["success", "already"]:
                    print(f"账号 {i} 签到成功: {msg}")
                    save_cookie_to_github_var(f"NS_COOKIE_{i}", new_cookie)
                    if hadsend:
                        send("NodeSeek 签到", f"账号{i}签到成功：{msg}")
                else:
                    print(f"账号 {i} 签到失败: {msg}")
            else:
                print(f"账号 {i} 登录失败")
                if hadsend:
                    send("NodeSeek 登录失败", f"账号{i}登录失败")
