from fastapi import HTTPException, status


class APIError(HTTPException):
    """Application-level HTTP error with a stable detail payload."""

    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(
            status_code=status_code,
            detail={"code": code, "message": message},
        )


def not_found(resource: str) -> APIError:
    return APIError(
        status.HTTP_404_NOT_FOUND,
        "RESOURCE_NOT_FOUND",
        f"{resource} not found.",
    )
