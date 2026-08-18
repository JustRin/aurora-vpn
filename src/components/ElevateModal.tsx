import { Modal } from "./ui";
import { api, errText } from "../lib/api";
import { useStore } from "../store";

/**
 * Offers to relaunch through UAC. Shown from two places: connecting in TUN mode
 * without rights, and registering elevated autostart (which writes a scheduled
 * task and therefore needs them once).
 */
export function ElevateModal({
  open,
  onClose,
  reason,
}: {
  open: boolean;
  onClose: () => void;
  reason: "tunnel" | "autostart";
}) {
  const toast = useStore((s) => s.toast);

  async function relaunch() {
    try {
      await api.relaunchElevated();
    } catch (e) {
      toast("error", "Перезапуск не удался", errText(e));
      onClose();
    }
  }

  return (
    <Modal
      open={open}
      title="Требуются права администратора"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button
            type="button"
            className="btn primary"
            onClick={() => void relaunch()}
          >
            Перезапустить
          </button>
        </>
      }
    >
      {reason === "tunnel" ? (
        <>
          <p style={{ margin: 0, color: "var(--text-dim)", fontSize: 13 }}>
            Режим TUN перехватывает трафик всей системы через виртуальный адаптер
            Wintun. Его создание требует прав администратора — Windows покажет
            запрос UAC.
          </p>
          <p style={{ margin: 0, color: "var(--text-muted)", fontSize: 12.5 }}>
            Если повышать права не нужно, переключитесь на режим системного
            прокси в настройках: он работает без UAC, но охватывает только те
            приложения, которые уважают системные настройки прокси.
          </p>
        </>
      ) : (
        <>
          <p style={{ margin: 0, color: "var(--text-dim)", fontSize: 13 }}>
            Автозапуск с правами администратора создаёт задачу в планировщике
            Windows — обычная запись в автозагрузке так не умеет, система не даёт
            повышать права без подтверждения.
          </p>
          <p style={{ margin: 0, color: "var(--text-muted)", fontSize: 12.5 }}>
            Права нужны только один раз, чтобы зарегистрировать задачу. После
            этого приложение будет стартовать с правами администратора само,
            без запроса UAC при каждом входе в систему.
          </p>
        </>
      )}
    </Modal>
  );
}
