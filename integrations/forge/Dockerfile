FROM node:24-bookworm-slim
WORKDIR /app
COPY integrations/forge ./integrations/forge
USER node
ENV NOVA_ANALYSIS_HOST=0.0.0.0
ENV PORT=4318
EXPOSE 4318
CMD ["node", "integrations/forge/server.mjs"]
