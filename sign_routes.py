
from flask import Blueprint, render_template, session, redirect, url_for, current_app
import sqlite3

from db import (
    get_user_by_id,
    get_medical_files_for_owner,
    get_signed_file_ids_for_owner,
)

sign_bp = Blueprint("sign", __name__)


@sign_bp.route("/sign", methods=["GET"])
def sign_page():
    user_id = session.get("user_id")

    if user_id is None:
        return redirect(url_for("login"))

    try:
        user = get_user_by_id(user_id)

        if user is None:
            session.clear()
            return redirect(url_for("login"))

        records = get_medical_files_for_owner(user_id)
        signed_ids = get_signed_file_ids_for_owner(user_id)

    except sqlite3.Error:
        return "Daftar dokumen tidak dapat diakses. Coba lagi nanti.", 503

    documents = [
        {
            "id": record["id"],
            "category": record["category"],
            "created_at": record["created_at"],
            "signed": record["id"] in signed_ids,
        }
        for record in records
    ]

    response = current_app.make_response(
        render_template(
            "sign.html",
            documents=documents,
            csrf_token=session.get("csrf_token"),
        )
    )

    response.headers["Cache-Control"] = "no-store"
    return response
