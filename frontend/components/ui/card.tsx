import * as React from "react"
import { cn } from "@/lib/utils"

function Card({
  className,
  size = "default",
  showTricolor = true,
  watermark = "SWYRA",
  children,
  ...props
}: React.ComponentProps<"div"> & { 
  size?: "default" | "sm"; 
  showTricolor?: boolean;
  watermark?: string | boolean;
}) {
  return (
    <div
      data-slot="card"
      data-size={size}
      className={cn(
        "relative overflow-hidden rounded-[26px] border border-border bg-card/60 backdrop-blur-2xl shadow-[0_8px_32px_0_rgba(0,0,0,0.3)] transition-transform duration-500 text-card-foreground",
        className
      )}
      {...props}
    >
      {/* M-Tricolor Top Stripe */}
      {showTricolor && (
        <div 
          className="h-[3px] w-full"
          style={{
            background: 'linear-gradient(to right, #0066B1 0%, #0066B1 33.3%, #1C69D4 33.3%, #1C69D4 66.6%, #E22718 66.6%, #E22718 100%)'
          }}
        />
      )}

      {/* SWYRA Precision Watermark */}
      {watermark && (
        <div className="absolute top-3.5 right-5 select-none pointer-events-none font-mono text-[10px] tracking-[0.25em] text-foreground/25 uppercase z-0 font-medium">
          {typeof watermark === 'string' ? watermark : 'SWYRA'}
        </div>
      )}

      <div className="relative z-10 w-full">
        {children}
      </div>
    </div>
  )
}

function CardHeader({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="card-header"
      className={cn(
        "flex flex-col space-y-1.5 p-8 sm:p-[34px] pb-0",
        className
      )}
      {...props}
    />
  )
}

function CardTitle({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="card-title"
      className={cn(
        "font-heading text-xl font-normal leading-none tracking-tight text-foreground",
        className
      )}
      {...props}
    />
  )
}

function CardDescription({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="card-description"
      className={cn("text-xs font-mono uppercase tracking-wider text-muted-foreground", className)}
      {...props}
    />
  )
}

function CardAction({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="card-action"
      className={cn(
        "col-start-2 row-span-2 row-start-1 self-start justify-self-end",
        className
      )}
      {...props}
    />
  )
}

function CardContent({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="card-content"
      className={cn("p-8 sm:p-[34px]", className)}
      {...props}
    />
  )
}

function CardFooter({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="card-footer"
      className={cn(
        "flex items-center p-8 sm:p-[34px] pt-0",
        className
      )}
      {...props}
    />
  )
}

export {
  Card,
  CardHeader,
  CardFooter,
  CardTitle,
  CardAction,
  CardDescription,
  CardContent,
}
