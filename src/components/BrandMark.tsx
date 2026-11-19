import { assetPath } from "../lib/api.ts";

export interface BrandMarkProps {
  className?: string;
}

/** The owner's finished transparent images, resized without altering the artwork. */
export function BrandMark({ className }: BrandMarkProps) {
  return (
    <span
      className={`ruijing-brand-mark ${className || ""}`}
      aria-hidden="true"
    >
      <img
        className="brand-image brand-image-black"
        src={assetPath("assets/ruijing-logo-black.png")}
        width="40"
        height="40"
        alt=""
        decoding="async"
      />
      <img
        className="brand-image brand-image-white"
        src={assetPath("assets/ruijing-logo-white.png")}
        width="40"
        height="40"
        alt=""
        decoding="async"
      />
    </span>
  );
}

