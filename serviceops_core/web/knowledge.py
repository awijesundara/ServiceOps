"""Knowledge base routes.

Moved from app.create_app(); endpoint names are unchanged."""
from flask import abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import audit, roles, tenant_query, visible_knowledge_query
from serviceops_models import db, Knowledge
from serviceops_core.localization import tr


def register(app):
    @app.get("/knowledge")
    @login_required
    def knowledge():
        q = request.args.get("q", "").strip()
        # Archived articles stay visible (labeled "Archived" in the template)
        # rather than disappearing; drafts are labeled and shown to reviewers only.
        query = visible_knowledge_query(current_user)
        if q:
            query = query.filter(db.or_(Knowledge.title.ilike(f"%{q}%"), Knowledge.body.ilike(f"%{q}%")))
        return render_template("knowledge.html", articles=query.order_by(Knowledge.created_at.desc()).all(), q=q)

    @app.route("/knowledge/new", methods=["GET", "POST"])
    @roles("agent", "manager", "admin")
    def knowledge_new():
        if request.method == "POST":
            article = Knowledge(title=request.form["title"], category=request.form["category"],
                                body=request.form["body"], author_id=current_user.id)
            db.session.add(article)
            db.session.flush()
            audit("create", f"KB{article.id:06d}", article.title)
            db.session.commit()
            return redirect(url_for("knowledge"))
        return render_template("knowledge_form.html")

    @app.get("/knowledge/<int:article_id>")
    @login_required
    def knowledge_detail(article_id):
        article = visible_knowledge_query(current_user).filter_by(id=article_id).first_or_404()
        history = tenant_query(Knowledge).filter_by(superseded_by_id=article.id).order_by(Knowledge.created_at.desc()).all()
        return render_template("knowledge_detail.html", article=article, history=history)

    @app.route("/knowledge/<int:article_id>/edit", methods=["GET", "POST"])
    @roles("agent", "manager", "admin")
    def knowledge_edit(article_id):
        article = tenant_query(Knowledge).filter_by(id=article_id).first_or_404()
        if article.archived:
            abort(409, description=tr("This article is archived. Create a new article instead of editing an archived version."))
        if request.method == "POST":
            if not article.published:
                # A never-published draft has no reader-facing history to
                # preserve, so it's published in place. Superseding it would
                # archive the unreviewed draft text, and archived versions are
                # readable by every role.
                article.title = request.form["title"]
                article.category = request.form["category"]
                article.body = request.form["body"]
                article.published = True
                audit("publish", f"KB{article.id:06d}", article.title)
                db.session.commit()
                flash(tr("Draft published."), "success")
                return redirect(url_for("knowledge_detail", article_id=article.id))
            new_version = Knowledge(
                title=request.form["title"], category=request.form["category"],
                body=request.form["body"], author_id=current_user.id, published=True,
            )
            db.session.add(new_version)
            db.session.flush()
            article.archived = True
            article.published = False
            article.superseded_by_id = new_version.id
            audit("supersede", f"KB{article.id:06d}", f"Replaced by KB{new_version.id:06d}")
            audit("create", f"KB{new_version.id:06d}", new_version.title)
            db.session.commit()
            flash(tr("Published an updated version. The previous version is preserved and archived."), "success")
            return redirect(url_for("knowledge_detail", article_id=new_version.id))
        return render_template("knowledge_form.html", article=article)

    @app.post("/knowledge/<int:article_id>/archive")
    @roles("agent", "manager", "admin")
    def knowledge_archive(article_id):
        article = tenant_query(Knowledge).filter_by(id=article_id).first_or_404()
        article.archived = True
        article.published = False
        audit("archive", f"KB{article.id:06d}", article.title)
        db.session.commit()
        flash(tr("Article archived. It no longer appears in knowledge search but its history is preserved."), "success")
        return redirect(url_for("knowledge_detail", article_id=article.id))
