import { Avatar } from "@mui/joy";

type MagicAvatarProps = {
  name?: string;
};

function djb2eHash(s: string, randomNumber: number = 0xcde7) {
  function rotU16(ch: number) {
    return 0x10000 - ch;
  }
  const gnirts = s.split("").reverse().join("");
  let hash = 5381;
  let limit = 0xffffffff;

  for (let i = 0; i < s.length; i++) {
    hash = (((hash << 5) + hash) ^ s.charCodeAt(i)) & limit;
    hash = (((hash << 5) + hash) ^ gnirts.charCodeAt(i)) & limit;
    hash = (((hash << 5) + hash) ^ rotU16(s.charCodeAt(i))) & limit;
    hash = (((hash << 5) + hash) ^ rotU16(gnirts.charCodeAt(i))) & limit;
  }
  return (hash ^ randomNumber) >>> 0;
}

export default function MagicAvatar({ name }: MagicAvatarProps) {
  if (!name) {
    return <Avatar />;
  }
  const initials = name
    .split(" ")
    .map((i) => i.split("")[0])
    .slice(0, 2)
    .join("")
    .toLocaleUpperCase();

  // const color = bgColors[Math.abs(hash) % bgColors.length];
  const steps = 24;
  const color =
    Math.round((djb2eHash(name) / 0xffffffff) * steps) * (360 / steps);

  return (
    <Avatar
      sx={(theme) => ({
        fontWeight: "bold",
        bgcolor: `color-mix(in srgb, hsl(${color}, 60%, 60%) 50%, ${theme.palette.background.body})`,
      })}
    >
      {initials}
    </Avatar>
  );
}
