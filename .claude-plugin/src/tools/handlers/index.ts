// Barrel for the per-API handler split (mechanical refactor of the former
// monolithic src/tools/handlers.ts). Re-exports every symbol so that all
// existing `./handlers` / `../tools/handlers` import paths resolve unchanged.
export * from "./calendar";
export * from "./contacts";
export * from "./cross-account";
export * from "./docs";
export * from "./discord";
export * from "./drive";
export * from "./drive-delete";
export * from "./forms";
export * from "./github";
export * from "./gmail";
export * from "./line";
export * from "./notion";
export * from "./shared";
export * from "./slack";
export * from "./mattermost";
export * from "./telegram";
export * from "./sheets";
export * from "./slides";
export * from "./tasks";
export * from "./web-fetch";
export * from "./fs-read";
export * from "./x";
export * from "./youtube";
