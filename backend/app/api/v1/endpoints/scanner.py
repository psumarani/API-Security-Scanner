"""Scanner catalog (modules, OWASP coverage, limits) and the dashboard summary."""

from fastapi import APIRouter

from app.api.deps import CurrentUser, DbSession
from app.scanner import registry
from app.scanner.engine import SCANNER_VERSION
from app.scanner.settings import ScanSettings
from app.schemas.scan import CategoryCoverageRead, DashboardSummary, ModuleInfo, ScannerCatalog
from app.services import scan_service

router = APIRouter(tags=["scanner"])


@router.get("/scanner/catalog", response_model=ScannerCatalog)
def catalog(_: CurrentUser) -> ScannerCatalog:
    fields = ScanSettings.model_fields
    limits = {
        name: {
            "min": next((m.ge for m in f.metadata if hasattr(m, "ge")), None),
            "max": next((m.le for m in f.metadata if hasattr(m, "le")), None),
            "default": f.default,
        }
        for name, f in fields.items()
        if f.default is not None
        and isinstance(f.default, int | float)
        and not isinstance(f.default, bool)
    }
    return ScannerCatalog(
        scanner_version=SCANNER_VERSION,
        modules=[
            ModuleInfo(
                id=m.id,
                name=m.name,
                description=m.description,
                categories=[c.value for c in m.categories],
                automated=m.automated,
                prerequisites=m.prerequisites,
                validation=m.validation,
                limitations=m.limitations,
                default_enabled=m.default_enabled,
            )
            for m in registry.list_modules()
        ],
        owasp_coverage=[CategoryCoverageRead(**c.__dict__) for c in registry.OWASP_COVERAGE],
        limits=limits,
    )


@router.get("/dashboard/summary", response_model=DashboardSummary)
def dashboard_summary(user: CurrentUser, db: DbSession) -> DashboardSummary:
    return scan_service.dashboard(db, user)
