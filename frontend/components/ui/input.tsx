import * as React from "react"

import { cn } from "@/lib/utils"

function Input({ className, type, ...props }: React.ComponentProps<"input">) {
  return (
    <input
      type={type}
      data-slot="input"
      className={cn(
        "h-12 w-full min-w-0 rounded-none border-0 border-b-2 border-border bg-transparent px-1 font-sans text-base text-foreground caret-accent transition-colors duration-300 placeholder:text-muted-foreground/50 focus:border-accent focus:outline-none focus:ring-0 focus:ring-offset-0 focus-visible:outline-none focus-visible:ring-0 disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50 aria-invalid:border-destructive md:text-sm",
        className
      )}
      {...props}
    />
  )
}

export { Input }
