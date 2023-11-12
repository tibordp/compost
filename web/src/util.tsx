export function formatFileSize(bytes: number, locale = "en-US") {
  const units = ["bytes", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
  let index = 0;

  while (bytes >= 1024 && index < units.length - 1) {
    bytes /= 1024;
    index++;
  }

  return (
    new Intl.NumberFormat(locale, { maximumFractionDigits: 2 }).format(bytes) +
    " " +
    units[index]
  );
}
