#include "struct.h"
#include "blog/manager/user_manager.h"
#include "blog/util.h"
#include "sylar/db/sqlite3.h"

namespace blog {

static sylar::Logger::ptr g_logger_access = SYLAR_LOG_NAME("access");

const std::string CookieKey::SESSION_KEY = "SSESSIONID";
const std::string CookieKey::USER_ID = "S_UID";
const std::string CookieKey::TOKEN = "S_TOKEN";
const std::string CookieKey::TOKEN_TIME = "S_TOKEN_TIME";
const std::string CookieKey::IS_AUTH= "IS_AUTH";
const std::string CookieKey::COMMENT_LAST_TIME = "COMMENT_LAST_TIME";
const std::string CookieKey::ARTICLE_LAST_TIME = "ARTICLE_LAST_TIME";
const std::string CookieKey::EMAIL_LAST_TIME = "EMAIL_LAST_TIME";

std::string GetRemoteIP(sylar::http::HttpRequest::ptr request
                        ,sylar::http::HttpSession::ptr session) {
    // http字段 X-Real-IP
    // 它用于告诉后端服务器实际客户端的 ip 地址，而不是代理服务器的 ip 地址
    auto rt = request->getHeader("X-Real-IP");
    if(!rt.empty()) {
        // 说明经过代理服务器，只需要返回这个真实 ip 即可
        return rt;
    }
    // 没有代理，那么就从 socket 中获取
    rt = session->getRemoteAddressString();
    auto pos = rt.find(':');
    return rt.substr(0, pos);
}

Result::Result(int32_t c, const std::string& m)
    :code(c)
    ,used(sylar::GetCurrentUS())
    ,msg(m){
}

std::string Result::toJsonString() const {
    Json::Value v;
    v["code"] = std::to_string(code);
    v["msg"] = msg;
    v["used"] = ((sylar::GetCurrentUS() - used) / 1000.0);
    if(!jsondata.isNull()) {
        v["data"] = jsondata;
    } else {
        //if(!datas.empty()) {
        //    auto& d = v["data"];
        //    for(auto& i : datas) {
        //        d[i.first] = i.second;
        //    }
        //}
    }
    return sylar::JsonUtil::ToString(v);
}

void Result::setResult(int32_t c, const std::string& m) {
    code = c;
    msg = m;
}

BlogServlet::BlogServlet(const std::string& name)
    :sylar::http::Servlet(name) {
}

int32_t BlogServlet::handle(sylar::http::HttpRequest::ptr request
                           ,sylar::http::HttpResponse::ptr response
                           ,sylar::http::HttpSession::ptr session) {
    uint64_t ts = sylar::GetCurrentUS();
    Result::ptr result = std::make_shared<Result>();
    // 跨域举例，请求 A，A 把请求转到 B 处理，这明显有安全风险，A 像是钓鱼网站，通常浏览器会屏蔽
    // B 可以利用 CORS 机制，设置 http 协议头 Access-Control-Allow-Origin: A，这样浏览器就不会屏蔽了
    // * 表示匹配所有，允许任何域名进行跨域
    response->setHeader("Access-Control-Allow-Origin", "*");
    // 跨域允许携带 cookies
    response->setHeader("Access-Control-Allow-Credentials", "true");
    if(handlePre(request, response, session, result)) {
        handle(request, response, session, result);
    } else {
        response->setBody(result->toJsonString());
    }
    uint64_t used = sylar::GetCurrentUS() - ts;
    handlePost(request, response, session, result);
    // 自定义头字段，用于捕捉请求的响应时间
    response->setHeader("used", std::to_string((used * 1.0 / 1000)) + "ms");
    return 0;
}

bool BlogServlet::handlePre(sylar::http::HttpRequest::ptr request
                           ,sylar::http::HttpResponse::ptr response
                           ,sylar::http::HttpSession::ptr session
                           ,Result::ptr result) {
    if(request->getPath() != "/user/login"
            && request->getPath() != "/user/logout") {
        // 这里主要更新用户信息
        initLogin(request, response, session);
    }
    if(request->getMethod() != sylar::http::HttpMethod::GET
            && request->getMethod() != sylar::http::HttpMethod::POST) {
        result->setResult(300, "invalid method");
        return false;
    }
    return true;
}

bool BlogServlet::handlePost(sylar::http::HttpRequest::ptr request
                           ,sylar::http::HttpResponse::ptr response
                           ,sylar::http::HttpSession::ptr session
                           ,Result::ptr result) {
    SYLAR_LOG_INFO(g_logger_access)
        << GetRemoteIP(request, session) << "\t"
        << request->getCookie(CookieKey::SESSION_KEY, "-") << "\t"
        << getUserId(request) << "\t"
        << result->code << "\t"
        << result->msg << "\t" << request->getPath()
        << "\t" << (!request->getQuery().empty() ? request->getQuery() : "-");
    return true;
}

sylar::http::SessionData::ptr BlogServlet::getSessionData(sylar::http::HttpRequest::ptr request
                                                          ,sylar::http::HttpResponse::ptr response) {
    // 获取 session id
    std::string sid = request->getCookie(CookieKey::SESSION_KEY);
    if(!sid.empty()) {
        auto data = sylar::http::SessionDataMgr::GetInstance()->get(sid);
        if(data) {
            // 已经存在 session_data ，直接返回
            return data;
        }
    }
    // 创建 session_data
    sylar::http::SessionData::ptr data(new sylar::http::SessionData(true));
    sylar::http::SessionDataMgr::GetInstance()->add(data);
    // 设置 cookie
    response->setCookie(CookieKey::SESSION_KEY, data->getId(), 0, "/");
    request->setCookie(CookieKey::SESSION_KEY, data->getId());
    return data;
}

bool BlogServlet::initLogin(sylar::http::HttpRequest::ptr request
                           ,sylar::http::HttpResponse::ptr response
                           ,sylar::http::HttpSession::ptr session) {
    auto data = getSessionData(request, response);
    int64_t uid = data->getData<int64_t>(CookieKey::USER_ID);
    if(uid) {
        // fast path
        return true;
    }
    int32_t is_auth = data->getData<int32_t>(CookieKey::IS_AUTH);
    if(is_auth) {
        // 没有 uid 但是 is_auth 为 true 明显是恶意修改的结果
        return false;
    }
    // slow path
    bool is_login = false;
    do {
        int64_t uid = request->getCookieAs<int64_t>(CookieKey::USER_ID);
        if(!uid) {
            break;
        }
        auto token = request->getCookie(CookieKey::TOKEN);
        if(token.empty()) {
            break;
        }
        int64_t token_time = request->getCookieAs<int64_t>(CookieKey::TOKEN_TIME);
        if(token_time <= time(0)) {
            break;
        }

        data::UserInfo::ptr uinfo = UserMgr::GetInstance()->get(uid);
        if(!uinfo) {
            break;
        }
        if(uinfo->getState() != 2) {
            break;
        }
        auto md5 = UserManager::GetToken(uinfo, token_time);
        // 验证服务器本地的用户信息和 cookie 的用户信息是否一致
        if(md5 != token) {
            SYLAR_LOG_INFO(g_logger_access)
                << GetRemoteIP(request, session) << "\t"
                << request->getCookie(CookieKey::SESSION_KEY, "-") << "\t"
                << uid << "\t"
                << 310 << "\t"
                << "invalid_token" << "\tauto_login" << request->getPath()
                << "\t" << (!request->getQuery().empty() ? request->getQuery() : "-");
            break;
        }
        // fast path，session_data 设置 uid，下次登录检查如果存在uid，无需验证
        data->setData(CookieKey::USER_ID, uid);
        is_login = true;
        SYLAR_LOG_INFO(g_logger_access)
            << GetRemoteIP(request, session) << "\t"
            << request->getCookie(CookieKey::SESSION_KEY, "-") << "\t"
            << uid << "\t"
            << 200 << "\t"
            << "ok" << "\tauto_login" << request->getPath()
            << "\t" << (!request->getQuery().empty() ? request->getQuery() : "-");
        // 刷新用户登录的时间
        uinfo->setLoginTime(time(0));
        auto db = getDB();
        if(db) {
            // 更新数据库用户信息记录
            data::UserInfoDao::Update(uinfo, db);
        }
        is_login = true;
    } while(0);
    data->setData(CookieKey::IS_AUTH, (int32_t)1);
    return is_login;
}

sylar::IDB::ptr BlogServlet::getDB() {
    return GetDB();
}

BlogLoginedServlet::BlogLoginedServlet(const std::string& name)
    :BlogServlet(name) {
}

bool BlogLoginedServlet::handlePre(sylar::http::HttpRequest::ptr request
                                   ,sylar::http::HttpResponse::ptr response
                                   ,sylar::http::HttpSession::ptr session
                                   ,Result::ptr result) {
    // 登录检查
    if(!initLogin(request, response, session)) {
        result->setResult(410, "not login");
        return false;
    }
    if(request->getMethod() != sylar::http::HttpMethod::GET
            && request->getMethod() != sylar::http::HttpMethod::POST) {
        result->setResult(300, "invalid method");
        return false;
    }
    return true;
}

int64_t BlogServlet::getUserId(sylar::http::HttpRequest::ptr request) {
    std::string sid = request->getCookie(CookieKey::SESSION_KEY);
    if(!sid.empty()) {
        auto data = sylar::http::SessionDataMgr::GetInstance()->get(sid);
        if(data) {
            return data->getData<int64_t>(CookieKey::USER_ID);
        }
    }
    return 0;
}

std::string BlogServlet::getCookieId(sylar::http::HttpRequest::ptr request) {
    return request->getCookie(CookieKey::SESSION_KEY);
}

}
