package dev.phonevault.signer;

import static org.junit.Assert.*;

import org.junit.Test;

public class BatteryStatusTest {
    private static final int DISCHARGING = 3, NOT_CHARGING = 4, UNPLUGGED = 0, USB = 2;

    @Test public void percentFromLevelAndScale() {
        assertEquals(87, BatteryStatus.of(87, 100, DISCHARGING, UNPLUGGED).percent);
        assertEquals(50, BatteryStatus.of(128, 256, DISCHARGING, UNPLUGGED).percent);
        assertEquals(100, BatteryStatus.of(120, 100, DISCHARGING, UNPLUGGED).percent);
        assertFalse(BatteryStatus.of(-1, 100, DISCHARGING, UNPLUGGED).known());
        assertFalse(BatteryStatus.of(50, 0, DISCHARGING, UNPLUGGED).known());
        assertEquals("87%", BatteryStatus.of(87, 100, DISCHARGING, UNPLUGGED).label());
        assertEquals("", BatteryStatus.UNKNOWN.label());
    }

    @Test public void chargingWhenPluggedOrReportedCharging() {
        assertTrue(BatteryStatus.of(40, 100, BatteryStatus.STATUS_CHARGING, UNPLUGGED).charging);
        assertTrue(BatteryStatus.of(100, 100, BatteryStatus.STATUS_FULL, UNPLUGGED).charging);
        assertTrue(BatteryStatus.of(40, 100, NOT_CHARGING, USB).charging);
        assertFalse(BatteryStatus.of(40, 100, DISCHARGING, UNPLUGGED).charging);
        assertEquals("Battery 40 percent, charging", BatteryStatus.of(40, 100, DISCHARGING, USB).description());
    }

    @Test public void lowOnlyBelowFifteenAndNotCharging() {
        assertTrue(BatteryStatus.of(14, 100, DISCHARGING, UNPLUGGED).low());
        assertFalse(BatteryStatus.of(15, 100, DISCHARGING, UNPLUGGED).low());
        assertFalse(BatteryStatus.of(5, 100, DISCHARGING, USB).low()); // on the charger: no nag
        assertFalse(BatteryStatus.UNKNOWN.low());
    }

    @Test public void glyphFill() {
        assertEquals(0, BatteryStatus.of(0, 100, DISCHARGING, UNPLUGGED).filledCells(8));
        assertEquals(1, BatteryStatus.of(2, 100, DISCHARGING, UNPLUGGED).filledCells(8));
        assertEquals(4, BatteryStatus.of(50, 100, DISCHARGING, UNPLUGGED).filledCells(8));
        assertEquals(8, BatteryStatus.of(100, 100, DISCHARGING, UNPLUGGED).filledCells(8));
        assertEquals(0, BatteryStatus.UNKNOWN.filledCells(8));
    }
}
