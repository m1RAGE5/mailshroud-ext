import { storage } from "#imports";

/**
 * Session state для зберігання розблокованих приватних ключів.
 * Використовує chrome.storage.session, який очищується при закритті браузера.
 *
 * Структура:
 * {
 *   email1: { armoredKey: string, timestamp: number },
 *   email2: { armoredKey: string, timestamp: number }
 * }
 */
export interface UnlockedKeyData {
  armoredKey: string;
  timestamp: number;
}

export const sessionState = storage.defineItem<Record<string, UnlockedKeyData>>(
  "session:unlockedKeys",
);

/**
 * Зберегти розблокований ключ у session storage
 */
export async function cacheUnlockedKey(
  email: string,
  armoredKey: string,
): Promise<void> {
  const current = (await sessionState.getValue()) || {};
  current[email] = {
    armoredKey,
    timestamp: Date.now(),
  };
  await sessionState.setValue(current);
}

/**
 * Отримати розблокований ключ з session storage
 */
export async function getCachedUnlockedKey(
  email: string,
): Promise<string | null> {
  const current = (await sessionState.getValue()) || {};
  const keyData = current[email];

  if (!keyData) return null;

  // Опціонально: можна додати перевірку на застарілість (наприклад, 30 хв)
  // const isExpired = Date.now() - keyData.timestamp > 30 * 60 * 1000;
  // if (isExpired) return null;

  return keyData.armoredKey;
}

/**
 * Видалити розблокований ключ з кешу
 */
export async function removeCachedUnlockedKey(email: string): Promise<void> {
  const current = (await sessionState.getValue()) || {};
  delete current[email];
  await sessionState.setValue(current);
}

/**
 * Очистити весь session cache (при logout або lock vault)
 */
export async function clearSessionCache(): Promise<void> {
  await sessionState.setValue({});
}
