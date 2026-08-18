/** Compile-once platform flag: the Android build drops desktop-only chrome
 * (window buttons, tray/autostart settings, elevation hints). */
export const IS_ANDROID = /android/i.test(navigator.userAgent);
