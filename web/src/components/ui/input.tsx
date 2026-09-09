import * as React from "react"

import { cn } from "@/lib/utils"

const Input = React.forwardRef<HTMLInputElement, React.ComponentProps<"input">>(
  ({ className, type, ...props }, ref) => {
    return (
      <input
        type={type}
        className={cn(
          "flex h-9 w-full rounded-lg border border-[var(--line)] bg-white px-3 py-1 text-[13px] text-[var(--ink)] outline-none transition-[border-color,box-shadow] placeholder:text-[var(--faint)] focus:border-[var(--line-strong)] focus:shadow-[0_0_0_4px_rgba(0,0,0,0.04)] disabled:cursor-not-allowed disabled:bg-[var(--canvas)] disabled:opacity-55",
          className
        )}
        ref={ref}
        {...props}
      />
    )
  }
)
Input.displayName = "Input"

export { Input }
