import * as React from "react"

import { cn } from "@/lib/utils"

const Textarea = React.forwardRef<
  HTMLTextAreaElement,
  React.ComponentProps<"textarea">
>(({ className, ...props }, ref) => {
  return (
    <textarea
      className={cn(
        "flex min-h-24 w-full resize-y rounded-xl border border-[var(--line)] bg-white px-3 py-2.5 text-[13px] leading-5 text-[var(--ink)] outline-none transition-[border-color,box-shadow] placeholder:text-[var(--faint)] focus:border-[var(--line-strong)] focus:shadow-[0_0_0_4px_rgba(0,0,0,0.04)] disabled:cursor-not-allowed disabled:bg-[var(--canvas)] disabled:opacity-55",
        className
      )}
      ref={ref}
      {...props}
    />
  )
})
Textarea.displayName = "Textarea"

export { Textarea }
