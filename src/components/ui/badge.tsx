import type { ComponentProps } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-sm px-1.5 py-0.5 font-mono text-xs font-medium tracking-wide",
  {
    variants: {
      tone: {
        neutral: "bg-muted text-muted-foreground",
        ok: "bg-ok/15 text-ok",
        warn: "bg-warn/15 text-warn",
        err: "bg-err/15 text-err",
        info: "bg-info/15 text-info",
      },
    },
    defaultVariants: { tone: "neutral" },
  },
);

function Badge({
  className,
  tone,
  ...props
}: ComponentProps<"span"> & VariantProps<typeof badgeVariants>) {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />;
}

export { Badge, badgeVariants };
