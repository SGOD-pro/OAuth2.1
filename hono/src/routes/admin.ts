import { Hono }
  from "hono";



const admin = new Hono();


admin.get(
  "/clients",
  async (c) => {
    const user =
      c.get("user");

    return c.json([]);
  }
);

admin.post(
  "/clients",
  async (c) => {
    return c.json({}, 201);
  }
);

admin.patch(
  "/clients/:id",
  async (c) => {
    return c.json({});
  }
);

admin.delete(
  "/clients/:id",
  async (c) => {
    return c.json({});
  }
);

admin.get(
  "/stats",
  async (c) => {
    return c.json({});
  }
);

admin.get(
  "/logs",
  async (c) => {
    return c.json([]);
  }
);

export default admin;