Fixed image optimization in the production container: Next.js standalone tracing omitted `sharp`'s native `libvips` library, so every image was served unoptimized
