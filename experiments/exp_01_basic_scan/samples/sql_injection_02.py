from django.db import connection
from django.http import HttpRequest, HttpResponse


def search_user(request: HttpRequest) -> HttpResponse:
    keyword = request.GET.get("q", "")
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT id, name FROM accounts WHERE name LIKE '%{keyword}%'")
        rows = cursor.fetchall()
    return HttpResponse(str(rows))
