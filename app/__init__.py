"""CyberTrace package init — app factory, db, logging."""
import logging
import os

from dotenv import load_dotenv
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect

load_dotenv()

db = SQLAlchemy()
csrf = CSRFProtect()


def create_app(test_config=None):
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object("config.Config")
    if test_config:
        app.config.update(test_config)

    os.makedirs(app.config["INSTANCE_DIR"], exist_ok=True)
    os.makedirs(app.config["REPORTS_DIR"], exist_ok=True)

    db.init_app(app)
    csrf.init_app(app)

    # Logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    app.logger.info("CyberTrace application startup")

    # Register blueprints (import here to avoid cycles)
    from app.routes.analysis import analysis_api, analysis_bp
    from app.routes.cases import cases_api, cases_bp
    from app.routes.custody import custody_api, custody_bp
    from app.routes.dashboard import dashboard_api, dashboard_bp
    from app.routes.evidence import evidence_api, evidence_bp
    from app.routes.integrity import integrity_api, integrity_bp
    from app.routes.reports import reports_api, reports_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(dashboard_api)
    app.register_blueprint(cases_bp)
    app.register_blueprint(cases_api)
    app.register_blueprint(evidence_bp)
    app.register_blueprint(evidence_api)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(analysis_api)
    app.register_blueprint(integrity_bp)
    app.register_blueprint(integrity_api)
    app.register_blueprint(custody_bp)
    app.register_blueprint(custody_api)
    app.register_blueprint(reports_bp)
    app.register_blueprint(reports_api)

    # Exempt JSON API blueprints from CSRF (session forms still protected).
    # NOTE: must pass the Blueprint objects — string names are not honoured
    # by CSRFProtect.exempt in current Flask-WTF versions.
    for _api_bp in (dashboard_api, cases_api, evidence_api, analysis_api,
                    integrity_api, custody_api, reports_api):
        csrf.exempt(_api_bp)

    # Import models so tables are known
    from app.models import case, custody, evidence, file_record, hash_record  # noqa: F401

    with app.app_context():
        db.create_all()

    @app.errorhandler(404)
    def not_found(e):
        from flask import render_template
        return render_template("base.html", error_message="Page not found (404)."), 404

    @app.errorhandler(500)
    def server_error(e):
        from flask import render_template
        app.logger.exception("Unhandled server error")
        # Never expose stack traces to the browser
        return render_template("base.html", error_message="An internal error occurred. Check logs."), 500

    return app
