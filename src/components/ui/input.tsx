import * as React from "react";
import { cn } from "@/lib/utils";

function Input({ className, type = "text", ...props }: React.ComponentProps<"input">) {
  return (
    <input
      type={type}
      className={cn(
        "flex h-11 w-full rounded-md bg-muted px-3 text-sm text-foreground outline-none",
        "shadow-[0_0_0_1px_rgb(255_255_255/0.08)] placeholder:text-subtle",
        "focus-visible:shadow-[0_0_0_1px_rgb(228_228_231/0.35)]",
        "disabled:cursor-not-allowed disabled:opacity-50",
        className,
      )}
      {...props}
      autoComplete={props.autoComplete ?? "off"}
    />
  );
}

function NativeSelect({ className, ...props }: React.ComponentProps<"select">) {
  return (
    <select
      className={cn(
        "flex h-11 rounded-md bg-muted px-3 text-sm text-foreground outline-none",
        "shadow-[0_0_0_1px_rgb(255_255_255/0.08)]",
        "focus-visible:shadow-[0_0_0_1px_rgb(228_228_231/0.35)]",
        className,
      )}
      {...props}
    />
  );
}

export { Input, NativeSelect };
