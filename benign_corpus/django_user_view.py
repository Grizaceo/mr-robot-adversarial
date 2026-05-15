"""Django view with parameterized ORM and auto-escaped templates — safe by design."""
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from .models import Article


@login_required
def article_detail(request, article_id):
    article = get_object_or_404(Article, pk=article_id)
    if article.author_id != request.user.id and not article.is_public:
        return HttpResponseForbidden("Not allowed")
    # ORM filter is parameterized — no SQL injection vector here.
    related = Article.objects.filter(tags__in=article.tags.all()).exclude(pk=article.pk)[:5]
    return render(request, "articles/detail.html", {
        "article": article,
        "related": related,
    })
