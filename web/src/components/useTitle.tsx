import React from "react";

export function useTitle(title?: string) {
  const desiredTitle = title ? `${title} - Compost Mail` : "Compost Mail";

  React.useEffect(() => {
    const prevTitle = document.title;
    document.title = desiredTitle;
    return () => {
      document.title = prevTitle;
    };
  }, [desiredTitle]);
}
