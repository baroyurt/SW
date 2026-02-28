<?php
// services/PortPanelSyncService.php
// Robust version using escaped direct SQL to avoid bind_param reference issues.
// Place this file at services/PortPanelSyncService.php (overwrite existing).

require_once __DIR__ . '/../core/Database.php';
require_once __DIR__ . '/../config.php';

class PortPanelSyncService {
    private $db;
    private $mysqli;
    private $cfg;

    public function __construct() {
        $this->db = Database::getInstance();
        $this->mysqli = $this->db->getConnection();
        $this->cfg = Config::get();
    }

    public function syncPortWithPanel(array $payload) {
        $switchId = intval($payload['switchId'] ?? 0);
        $portNo = intval($payload['port'] ?? 0);
        if ($switchId <= 0 || $portNo <= 0) {
            throw new Exception("Invalid switchId or port");
        }

        return $this->db->withRetry(function() use ($payload, $switchId, $portNo) {
            $this->mysqli->begin_transaction();

            try {
                // Load switch
                $sql = "SELECT s.*, r.id as rack_id, r.name as rack_name
                        FROM switches s
                        LEFT JOIN racks r ON s.rack_id = r.id
                        WHERE s.id = " . intval($switchId) . " LIMIT 1";
                $res = $this->mysqli->query($sql);
                if (!$res) throw new Exception("Switch select failed: " . $this->mysqli->error);
                $switch = $res->fetch_assoc();
                if (!$switch) throw new Exception("Switch not found");

                $isFiberPort = $portNo > ($switch['ports'] - 4);

                $panelId = isset($payload['panelId']) ? intval($payload['panelId']) : null;
                $panelPort = isset($payload['panelPort']) ? intval($payload['panelPort']) : null;
                $panelType = isset($payload['panelType']) ? $payload['panelType'] : null;

                $panelInfo = null;
                if ($panelId && $panelPort) {
                    if (!in_array($panelType, ['patch','fiber'])) throw new Exception("Invalid panelType");
                    $tbl = $panelType === 'patch' ? 'patch_panels' : 'fiber_panels';
                    $sql = "SELECT * FROM `{$tbl}` WHERE id = " . intval($panelId) . " LIMIT 1 FOR UPDATE";
                    $res = $this->mysqli->query($sql);
                    if (!$res) throw new Exception("Panel select failed: " . $this->mysqli->error);
                    $panelInfo = $res->fetch_assoc();
                    if (!$panelInfo) throw new Exception("Panel not found");
                    if ($panelInfo['rack_id'] != $switch['rack_id']) throw new Exception("Panel in different rack");
                    if ($panelType === 'patch' && $isFiberPort) throw new Exception("Patch panel cannot connect to fiber port");
                    if ($panelType === 'fiber' && !$isFiberPort) throw new Exception("Fiber panel requires fiber port");
                }

                // Lock ports row
                $sql = "SELECT * FROM ports WHERE switch_id = " . intval($switchId) . " AND port_no = " . intval($portNo) . " FOR UPDATE";
                $res = $this->mysqli->query($sql);
                if ($res === false) throw new Exception("Ports select failed: " . $this->mysqli->error);
                $portRow = $res->fetch_assoc();

                // Values (prefer payload, otherwise existing)
                $type = $this->mysqli->real_escape_string($payload['type'] ?? ($portRow['type'] ?? 'BOŞ'));
                $device = $this->mysqli->real_escape_string($payload['device'] ?? ($portRow['device'] ?? ''));
                $ip = $this->mysqli->real_escape_string($payload['ip'] ?? ($portRow['ip'] ?? ''));
                $mac = $this->mysqli->real_escape_string($payload['mac'] ?? ($portRow['mac'] ?? ''));
                $connectionInfo = $this->mysqli->real_escape_string($payload['connectionInfo'] ?? ($portRow['connection_info_preserved'] ?? ''));

                if ($portRow) {
                    $currentSync = intval($portRow['sync_version'] ?? 1);
                    $newSync = $currentSync + 1;

                    $connected_panel_id = $panelId ? intval($panelId) : ($portRow['connected_panel_id'] !== null ? intval($portRow['connected_panel_id']) : null);
                    $connected_panel_port = $panelPort ? intval($panelPort) : ($portRow['connected_panel_port'] !== null ? intval($portRow['connected_panel_port']) : null);

                    $connected_to = $connected_panel_id ? ($this->mysqli->real_escape_string($switch['rack_name'] . '-' . ($panelInfo['panel_letter'] ?? '') . ($connected_panel_port ?? ''))) : ($portRow['connected_to'] !== null ? $this->mysqli->real_escape_string($portRow['connected_to']) : null);

                    $sql = "UPDATE ports SET
                                type = '{$type}',
                                device = '{$device}',
                                ip = '{$ip}',
                                mac = '{$mac}',
                                connected_panel_id = " . ($connected_panel_id !== null ? intval($connected_panel_id) : "NULL") . ",
                                connected_panel_port = " . ($connected_panel_port !== null ? intval($connected_panel_port) : "NULL") . ",
                                connection_info_preserved = '" . $connectionInfo . "',
                                connected_to = " . ($connected_to !== null ? "'" . $connected_to . "'" : "NULL") . ",
                                sync_version = " . intval($newSync) . "
                            WHERE id = " . intval($portRow['id']) . " AND sync_version = " . intval($currentSync);

                    if (!$this->mysqli->query($sql)) {
                        throw new Exception("Failed to update ports: " . $this->mysqli->error);
                    }

                    $oldPortValues = [
                        'type' => $portRow['type'],
                        'device' => $portRow['device'],
                        'ip' => $portRow['ip'],
                        'mac' => $portRow['mac'],
                        'connected_panel_id' => $portRow['connected_panel_id'],
                        'connected_panel_port' => $portRow['connected_panel_port']
                    ];
                } else {
                    // Insert new ports row
                    $connected_to_sql = $connected_panel_id ? ("'" . $this->mysqli->real_escape_string($switch['rack_name'] . '-' . ($panelInfo['panel_letter'] ?? '') . $panelPort) . "'") : "NULL";
                    $sql = "INSERT INTO ports (switch_id, port_no, type, device, ip, mac, connected_panel_id, connected_panel_port, connection_info_preserved, connected_to, sync_version)
                            VALUES (" . intval($switchId) . ", " . intval($portNo) . ",
                                    '{$type}', '{$device}', '{$ip}', '{$mac}',
                                    " . ($panelId !== null ? intval($panelId) : "NULL") . ",
                                    " . ($panelPort !== null ? intval($panelPort) : "NULL") . ",
                                    '{$connectionInfo}', {$connected_to_sql}, 1)";
                    if (!$this->mysqli->query($sql)) {
                        throw new Exception("Failed to insert ports: " . $this->mysqli->error);
                    }
                    $oldPortValues = null;
                }

                // Panel side update/insert
                $connDetailsArr = [
                    'switch_id' => $switchId,
                    'switch_name' => $switch['name'],
                    'switch_port' => $portNo,
                    'device' => $payload['device'] ?? '',
                    'ip' => $payload['ip'] ?? '',
                    'mac' => $payload['mac'] ?? '',
                    'synced_at' => date('Y-m-d H:i:s'),
                    'synced_by' => $this->cfg['current_user'] ?? 'system'
                ];
                $connDetails = $this->mysqli->real_escape_string(json_encode($connDetailsArr, JSON_UNESCAPED_UNICODE));

                $oldPanelValues = null;
                if ($panelId && $panelPort) {
                    if ($panelType === 'patch') {
                        $sql = "SELECT * FROM patch_ports WHERE panel_id = " . intval($panelId) . " AND port_number = " . intval($panelPort) . " FOR UPDATE";
                        $res = $this->mysqli->query($sql);
                        if ($res === false) throw new Exception("patch_ports select failed: " . $this->mysqli->error);
                        $prow = $res->fetch_assoc();

                        $connected_to_text = $this->mysqli->real_escape_string($switch['name'] . '-Port' . $portNo);

                        if ($prow) {
                            $pv = intval($prow['sync_version'] ?? 1);
                            $nv = $pv + 1;
                            $sql = "UPDATE patch_ports SET
                                        status = 'active',
                                        connected_to = '{$connected_to_text}',
                                        connected_switch_id = " . intval($switchId) . ",
                                        connected_switch_port = " . intval($portNo) . ",
                                        connection_details = '{$connDetails}',
                                        sync_version = " . intval($nv) . "
                                    WHERE id = " . intval($prow['id']) . " AND sync_version = " . intval($pv);
                            if (!$this->mysqli->query($sql)) throw new Exception("patch_ports update failed: " . $this->mysqli->error);
                            $oldPanelValues = ['connected_switch_id' => $prow['connected_switch_id'], 'connected_switch_port' => $prow['connected_switch_port']];
                        } else {
                            $sql = "INSERT INTO patch_ports (panel_id, port_number, status, connected_to, connected_switch_id, connected_switch_port, connection_details, sync_version)
                                    VALUES (" . intval($panelId) . ", " . intval($panelPort) . ", 'active', '{$connected_to_text}', " . intval($switchId) . ", " . intval($portNo) . ", '{$connDetails}', 1)";
                            if (!$this->mysqli->query($sql)) throw new Exception("patch_ports insert failed: " . $this->mysqli->error);
                            $oldPanelValues = null;
                        }
                    } else {
                        // fiber
                        $sql = "SELECT * FROM fiber_ports WHERE panel_id = " . intval($panelId) . " AND port_number = " . intval($panelPort) . " FOR UPDATE";
                        $res = $this->mysqli->query($sql);
                        if ($res === false) throw new Exception("fiber_ports select failed: " . $this->mysqli->error);
                        $prow = $res->fetch_assoc();

                        $connected_to_text = $this->mysqli->real_escape_string($switch['name'] . '-Port' . $portNo);

                        if ($prow) {
                            $pv = intval($prow['sync_version'] ?? 1);
                            $nv = $pv + 1;
                            $sql = "UPDATE fiber_ports SET
                                        status = 'active',
                                        connected_to = '{$connected_to_text}',
                                        connected_switch_id = " . intval($switchId) . ",
                                        connected_switch_port = " . intval($portNo) . ",
                                        connection_type = 'switch_fiber',
                                        connection_details = '{$connDetails}',
                                        sync_version = " . intval($nv) . "
                                    WHERE id = " . intval($prow['id']) . " AND sync_version = " . intval($pv);
                            if (!$this->mysqli->query($sql)) throw new Exception("fiber_ports update failed: " . $this->mysqli->error);
                            $oldPanelValues = ['connected_switch_id' => $prow['connected_switch_id'], 'connected_switch_port' => $prow['connected_switch_port']];
                        } else {
                            $sql = "INSERT INTO fiber_ports (panel_id, port_number, status, connected_to, connected_switch_id, connected_switch_port, connection_type, connection_details, sync_version)
                                    VALUES (" . intval($panelId) . ", " . intval($panelPort) . ", 'active', '{$connected_to_text}', " . intval($switchId) . ", " . intval($portNo) . ", 'switch_fiber', '{$connDetails}', 1)";
                            if (!$this->mysqli->query($sql)) throw new Exception("fiber_ports insert failed: " . $this->mysqli->error);
                            $oldPanelValues = null;
                        }
                    }
                }

                // connection_history insert (audit)
                $user = $this->mysqli->real_escape_string($this->cfg['current_user'] ?? 'system');
                $connectionType = $panelType === 'fiber' ? 'switch_to_fiber' : 'switch_to_patch';
                $action = ($oldPortValues || $oldPanelValues) ? 'updated' : 'created';
                $oldValues = $this->mysqli->real_escape_string(json_encode(['port' => $oldPortValues, 'panel_port' => $oldPanelValues], JSON_UNESCAPED_UNICODE));
                $newValues = $this->mysqli->real_escape_string(json_encode(['port' => ['type'=>$type,'device'=>$device,'ip'=>$ip,'mac'=>$mac], 'panel_port' => ['panel_id'=>$panelId,'panel_port'=>$panelPort]], JSON_UNESCAPED_UNICODE));
                $targetType = $panelType ? ($panelType === 'patch' ? 'patch_panel' : 'fiber_panel') : 'none';
                $targetId = $panelId !== null ? intval($panelId) : 0;
                $targetPort = $panelPort !== null ? intval($panelPort) : 0;

                $sql = "INSERT INTO connection_history
                        (user_name, connection_type, source_type, source_id, source_port, target_type, target_id, target_port, action, old_values, new_values)
                        VALUES ('{$user}', '{$connectionType}', 'switch', " . intval($switchId) . ", " . intval($portNo) . ", '{$targetType}', {$targetId}, {$targetPort}, '{$action}', '{$oldValues}', '{$newValues}')";
                if (!$this->mysqli->query($sql)) throw new Exception("connection_history insert failed: " . $this->mysqli->error);

                $this->mysqli->commit();

                return ['success' => true, 'message' => 'Senkronizasyon başarılı'];
            } catch (Exception $e) {
                try { $this->mysqli->rollback(); } catch (Exception $ignore) {}
                throw $e;
            }
        }, intval($this->cfg['retry_max'] ?? 3));
    }
}
?>