# 样本: SQL注入 - Python Django f-string
# 期望: 检测到 SQL 注入（f-string 直接插入用户输入到 raw 查询）
from django.db import connection
from django.http import HttpRequest, HttpResponse


def search_user(request: HttpRequest) -> HttpResponse:
    keyword = request.GET.get("q", "")
    with connection.cursor() as cursor:
        # 漏洞：使用 f-string 直接嵌入用户输入
        cursor.execute(f"SELECT id, name FROM accounts WHERE name LIKE '%{keyword}%'")
        rows = cursor.fetchall()
    return HttpResponse(str(rows))
