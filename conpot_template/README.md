# Custom Conpot template

A modified copy of Conpot 0.6.0's `default` template. The only functional change from
stock is **Modbus slave 1**, which now models a small pumping / water-treatment station so
a standard Modbus client reads **real process data at address 0** (instead of the stock
template's `IllegalAddress`), and an attacker's **write is accepted and persists** — a far
more convincing demo and a realistic "tamper".

Baked into the image by the repo `Dockerfile` (`docker build -t conpot-ics:latest .`).
Everything else (S7comm, SNMP, HTTP, BACnet, etc.) is unchanged from stock. The stock
`ssl/` dir (an unused HTTPS/proxy cert + private key) is intentionally omitted — Conpot
starts and serves fine without it, and no key is committed.

## Modbus slave 1 register map (all blocks start at address 0)

Values are fixed (not random) so a demo capture is reproducible. Edit them in
`modbus/modbus.xml` (block definitions) and `template.xml` (the `databus` values).

**Coils — FC1 read / FC5 write** (`[1,1,1,1,1,0,0,0, ...]`)

| addr | meaning        | addr | meaning        |
|------|----------------|------|----------------|
| 0    | pump1_run      | 4    | chlorine_dosing|
| 1    | pump2_run      | 5    | backwash       |
| 2    | inlet_valve    | 6    | standby_pump   |
| 3    | outlet_valve   | 7    | fault_latch    |

**Discrete inputs — FC2 read-only** (`[1,0,0,0,0,0,1,0, ...]`)

| addr | meaning        | addr | meaning        |
|------|----------------|------|----------------|
| 0    | mains_ok       | 4    | low_level      |
| 1    | pump1_overload | 5    | door_open      |
| 2    | pump2_overload | 6    | estop_ok       |
| 3    | high_level     | 7    | leak_detected  |

**Holding registers — FC3 read / FC6·FC16 write** (`[1480,1465,85,20,650,0,500,0, ...]`)

| addr | meaning               | addr | meaning                |
|------|-----------------------|------|------------------------|
| 0    | pump1_speed_rpm       | 4    | chlorine_setpoint_ppb  |
| 1    | pump2_speed_rpm       | 5    | control_mode (0=auto)  |
| 2    | tank_hi_setpoint_pct  | 6    | pressure_setpoint_kpa  |
| 3    | tank_lo_setpoint_pct  | 7    | alarm_reset            |

**Input registers (ANALOG_INPUTS) — FC4 read-only** (`[412,538,1260,236,74,18,142,139, ...]`)

| addr | meaning              | addr | meaning              |
|------|----------------------|------|----------------------|
| 0    | inlet_pressure_kpa   | 4    | tank_level_pct       |
| 1    | outlet_pressure_kpa  | 5    | turbidity_ntu_x10    |
| 2    | flow_l_min           | 6    | pump1_current_0.1A   |
| 3    | water_temp_0.1C      | 7    | pump2_current_0.1A   |

(Scaled integers where Modbus has no floats: temp 236 = 23.6 °C, current 142 = 14.2 A.)
