import * as React from "react"

import { cn } from "@/lib/utils"

const Textarea = React.forwardRef<
  HTMLTextAreaElement,
  React.ComponentProps<"textarea">
>(({ className, ...props }, ref) => {
  return (
    <textarea
      className={cn(
        "flex min-h-24 w-full resize-y rounded-[var(--radius-control)] border-[1.5px] border-[var(--outline)] bg-white px-3 py-2 text-[13px] leading-5 text-[var(--ink)] outline-none transition-[box-shadow] placeholder:text-[var(--faint)] focus:shadow-[0_0_0_3px_var(--main-soft)] disabled:cursor-not-allowed disabled:bg-[var(--canvas)] disabled:opacity-55",
        className
      )}
      ref={ref}
      {...props}
    />
  )
})
Textarea.displayName = "Textarea"

export { Textarea }
