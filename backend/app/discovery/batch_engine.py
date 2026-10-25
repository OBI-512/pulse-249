import asyncio

from sqlalchemy.ext.asyncio import AsyncSession

from ..models import DiscoveryJob, DiscoveryResult
from .models import DiscoveryContext
from .registry import registry


class BatchDiscoveryEngine:
    async def run(
        self,
        job: DiscoveryJob,
        targets: list[str],
        methods: list[str],
        timeout_seconds: float,
        concurrency: int,
        db: AsyncSession,
        http_port: int | None = None,
        https_port: int | None = None,
        snmp_context: dict[str, object] | None = None,
    ) -> list[DiscoveryResult]:

        semaphore = asyncio.Semaphore(concurrency)

        async def run_target(ip_address: str):
            async with semaphore:
                target_results = []

                for method in methods:
                    adapter = registry.get(method)

                    if adapter is None:
                        raise ValueError(
                            f"Unsupported discovery method: {method}"
                        )

                    result = await adapter.discover(
                        DiscoveryContext(
                            ip_address=ip_address,
                            timeout_seconds=timeout_seconds,
                            http_port=http_port,
                            https_port=https_port,
                            **(snmp_context or {}),
                        )
                    )

                    record = DiscoveryResult(
                        discovery_job_id=job.id,
                        ip_address=result.ip_address,
                        discovery_method=result.method,
                        status=(
                            "DISCOVERED"
                            if result.success
                            else "UNREACHABLE"
                        ),
                        vendor=result.vendor,
                        model=result.model,
                        hostname=result.hostname,
                        serial_number=result.serial_number,
                        raw_data={
                            **result.raw_data,
                            "message": result.message,
                            "response_time_ms": result.response_time_ms,
                            "management_protocol": (
                                result.management_protocol
                            ),
                        },
                    )

                    target_results.append(record)

                return target_results

        records: list[DiscoveryResult] = []

        chunk_size = max(1, concurrency)

        for index in range(0, len(targets), chunk_size):
            chunk = targets[index:index + chunk_size]

            batches = await asyncio.gather(
                *(run_target(target) for target in chunk)
            )

            for batch in batches:
                records.extend(batch)

        db.add_all(records)
        await db.flush()

        return records
