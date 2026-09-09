import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2 py-0.5 font-mono text-[10px] font-medium uppercase tabular-nums transition-colors focus:outline-none focus-visible:ring-4 focus-visible:ring-black/[0.05]",
  {
    variants: {
      variant: {
        default:
          "border-[var(--line)] bg-[var(--primary-soft)] text-[var(--ink)]",
        secondary:
          "border-[var(--line)] bg-white text-[var(--subtext)]",
        destructive:
          "border-[var(--danger)] bg-white text-[var(--danger)]",
        success:
          "border-[var(--success)] bg-white text-[var(--success)]",
        warning:
          "border-[var(--warning)] bg-white text-[var(--warning)]",
        danger:
          "border-[var(--danger)] bg-white text-[var(--danger)]",
        outline: "border-[var(--line)] bg-transparent text-[var(--ink)]",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  )
}

export { Badge, badgeVariants }
