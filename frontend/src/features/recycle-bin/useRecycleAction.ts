import { useCallback } from "react";
import { ApiError, apiFetch } from "../../api/client";
import { useDialog } from "../../components/common/DialogSystem";
import { useFeedback } from "../../components/common/FeedbackSystem";
import { friendlyErrorNotice } from "../../utils/feedback";

export function useRecycleAction(token: string) {
  const dialog = useDialog();
  const feedback = useFeedback();

  return useCallback(async (entityType: string, id: string, label: string, deletePath: string) => {
    const preview = await apiFetch<any>(`/recycle-bin/preview?entity_type=${entityType}&entity_id=${id}`, {}, token);
    if (preview.blockers?.length) {
      const synthetic = new ApiError("Deletion blocked", 409, "RECYCLE_DEPENDENCIES_PRESENT", { conflicts: preview.blockers });
      const notice = friendlyErrorNotice(synthetic, `Unable to delete ${entityType.toLowerCase()}.`, { action: "delete", entityType, entityName: label });
      feedback.error(notice.message, `Cannot delete ${label}`);
      return false;
    }

    const bundled = Array.isArray(preview.bundled_items) ? preview.bundled_items : [];
    const bundledByType = (type: string) => bundled.filter((item: any) => item?.entity_type === type);
    const customers = bundledByType("CUSTOMER");
    const services = bundledByType("CUSTOMER_SERVICE");
    const nestings = bundledByType("DEVICE_GROUP_NESTING");
    const memberships = bundledByType("DEVICE_GROUP_MEMBERSHIP");
    const labels = (items: any[]) => items.map((item: any) => item?.display_snapshot?.label).filter(Boolean);

    let message = `Move ${label} to the Recycle Bin?`;
    if (entityType === "CUSTOMER" && services.length) {
      const serviceNames = labels(services);
      message += ` This will also move ${services.length === 1 ? `its service ${serviceNames[0] || "record"}` : `${services.length} attached services`} to the same recoverable recycle batch.`;
    } else if (entityType === "DEVICE" && (customers.length || services.length)) {
      const customerNames = labels(customers);
      const serviceNames = labels(services);
      const details = [
        customers.length ? `${customers.length === 1 ? `customer ${customerNames[0] || "record"}` : `${customers.length} customers`}` : "",
        services.length ? `${services.length === 1 ? `service ${serviceNames[0] || "record"}` : `${services.length} services`}` : "",
      ].filter(Boolean).join(" and ");
      message += ` This access point is serving a customer. The same action will also move ${details} to the Recycle Bin.`;
    } else if (entityType === "DEVICE_GROUP" && (nestings.length || memberships.length)) {
      message += " Its direct device memberships and parent/child group links will be removed with the group. The devices and the other groups themselves will not be deleted.";
    }

    if (!await dialog.confirm({ title: "Move to Recycle Bin", message, confirmLabel: "Move to Recycle Bin", tone: "danger" })) return false;
    await apiFetch(deletePath + (deletePath.includes("?") ? "&" : "?") + "confirmed=true", { method: "DELETE" }, token);
    return true;
  }, [dialog, feedback, token]);
}
