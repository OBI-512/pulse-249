from sqlalchemy.ext.asyncio import AsyncSession

from ..models import DiscoveryJob, DiscoveryResult as DiscoveryResultModel
from .models import DiscoveryContext
from .registry import registry


class DiscoveryEngine:
    async def run(
        self,
        context: DiscoveryContext,
        methods: list[str],
        db: AsyncSession,
        job: DiscoveryJob,
    ) -> list[DiscoveryResultModel]:
        results = []

        for method in methods:
            adapter = registry.get(method)
            if adapter is None:
                raise ValueError(f"Unsupported discovery method: {method}")

            result = await adapter.discover(context)
            record = DiscoveryResultModel(
                discovery_job_id=job.id,
                ip_address=result.ip_address,
                discovery_method=result.method,
                status="DISCOVERED" if result.success else "UNREACHABLE",
                vendor=result.vendor,
                model=result.model,
                hostname=result.hostname,
                serial_number=result.serial_number,
                raw_data={
                    **result.raw_data,
                    "message": result.message,
                    "response_time_ms": result.response_time_ms,
                    "management_protocol": result.management_protocol,
                },
            )
            db.add(record)
            results.append(record)

        await db.flush()
        return results


discovery_engine = DiscoveryEngine()
