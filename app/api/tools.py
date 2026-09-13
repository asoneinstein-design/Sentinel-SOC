from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.environment.simulator import SOCEnvironment

router = APIRouter(prefix="/api/tools", tags=["tools"])

# Keep one shared simulated environment instance
environment = SOCEnvironment()


class OperationRequest(BaseModel):
    operation: str
    target: str


@router.get("")
def list_tools():
    return {
        "tools": [
            {
                "name": "firewall_block",
                "description": "Block a source IP in the simulated firewall.",
                "allowed": True,
            },
            {
                "name": "quarantine_host",
                "description": "Isolate a compromised host.",
                "allowed": True,
            },
        ]
    }


@router.post("/execute")
def execute_operation(request: OperationRequest):

    operation = request.operation
    target = request.target

    if not target:
        raise HTTPException(
            status_code=400,
            detail="Target cannot be empty.",
        )

    try:

        if operation == "firewall_block":

            rule = environment.block_ip(
                target,
                reason="Manual dashboard containment action",
            )

            return {
                "success": True,
                "operation": operation,
                "target": target,
                "result": {
                    "rule_id": rule.rule_id,
                    "ip": rule.ip,
                    "blocked": rule.blocked,
                    "reason": rule.reason,
                    "created_at": rule.created_at,
                },
            }

        elif operation == "quarantine_host":

            success = environment.quarantine_host(target)

            if not success:
                raise HTTPException(
                    status_code=404,
                    detail=f"Host '{target}' not found.",
                )

            return {
                "success": True,
                "operation": operation,
                "target": target,
                "result": {
                    "isolated": True,
                },
            }

        else:

            raise HTTPException(
                status_code=400,
                detail=f"Unsupported operation: {operation}",
            )

    except HTTPException:
        raise

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )