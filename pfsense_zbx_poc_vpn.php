<?php
/**
 * pfsense_zbx_poc_vpn.php
 * Version: 0.24.7-baitz.11-poc-vpn.2
 *
 * POC somente leitura para observabilidade de peers VPN no pfSense.
 * Não altera rotas, gateways, serviços, IPsec, OpenVPN ou configuração.
 *
 * Comandos:
 *   discovery_ipsec
 *   probe_ipsec <IKEID>
 *   discovery_openvpn_client
 *   probe_openvpn_client <VPNID>
 */

define('POC_VERSION', '0.24.7-baitz.11-poc-vpn.2');
define('PING_COUNT', 4);
define('PING_WAIT_MS', 1000);
define('STATE_DIR', '/tmp');

require_once('globals.inc');
require_once('functions.inc');
require_once('config.inc');
require_once('util.inc');
require_once('ipsec.inc');
require_once('openvpn.inc');

function poc_json($data) {
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

function poc_safe($value) {
    return preg_replace('/[^0-9A-Za-z_.-]/', '_', (string)$value);
}

function poc_resolve($remote) {
    $remote = trim((string)$remote);
    if ($remote === '') {
        return '';
    }
    if (filter_var($remote, FILTER_VALIDATE_IP)) {
        return $remote;
    }
    $resolved = gethostbyname($remote);
    return filter_var($resolved, FILTER_VALIDATE_IP) ? $resolved : '';
}

function poc_peer_state($scope, $id, $remote, $resolved) {
    $file = STATE_DIR . '/pfz_vpnpoc_' . poc_safe($scope) . '_' . poc_safe($id) . '.json';
    $now = time();
    $previous = [];

    if (file_exists($file)) {
        $tmp = json_decode(@file_get_contents($file), true);
        if (is_array($tmp)) {
            $previous = $tmp;
        }
    }

    $changed = 0;
    $last_change = isset($previous['last_change_epoch']) ? (int)$previous['last_change_epoch'] : $now;

    $previous_resolved = isset($previous['resolved_ip']) ? (string)$previous['resolved_ip'] : '';
    $previous_remote = isset($previous['remote_gateway']) ? (string)$previous['remote_gateway'] : '';

    if (
        ($previous_resolved !== '' && $resolved !== '' && $previous_resolved !== $resolved) ||
        ($previous_remote !== '' && $remote !== '' && $previous_remote !== $remote)
    ) {
        $changed = 1;
        $last_change = $now;
    }

    @file_put_contents($file, json_encode([
        'remote_gateway' => $remote,
        'resolved_ip' => $resolved,
        'last_change_epoch' => $last_change
    ]));

    return [$changed, $last_change];
}

function poc_ping($ip) {
    $result = [
        'reachable' => 0,
        'loss_pct' => 100.0,
        'rtt_min_ms' => 0.0,
        'rtt_avg_ms' => 0.0,
        'rtt_max_ms' => 0.0,
        'jitter_ms' => 0.0,
        'error' => ''
    ];

    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        $result['error'] = 'invalid_or_unresolved_ip';
        return $result;
    }

    $out = [];
    $rc = 0;
    $cmd = '/sbin/ping -c ' . PING_COUNT . ' -W ' . PING_WAIT_MS . ' ' . escapeshellarg($ip) . ' 2>&1';
    @exec($cmd, $out, $rc);
    $txt = implode("\n", $out);

    if (preg_match('/([0-9.]+)% packet loss/i', $txt, $m)) {
        $result['loss_pct'] = (float)$m[1];
        $result['reachable'] = ($result['loss_pct'] < 100.0) ? 1 : 0;
    }

    if (preg_match('/(?:round-trip|round trip).*?=\s*([0-9.]+)\/([0-9.]+)\/([0-9.]+)\/([0-9.]+)\s*ms/i', $txt, $m)) {
        $result['rtt_min_ms'] = (float)$m[1];
        $result['rtt_avg_ms'] = (float)$m[2];
        $result['rtt_max_ms'] = (float)$m[3];
        $result['jitter_ms'] = (float)$m[4];
    }

    if ($result['reachable'] === 0 && $rc !== 0 && $result['error'] === '') {
        $result['error'] = 'icmp_unreachable_or_blocked';
    }

    return $result;
}

function poc_base_probe($scope, $id, $name, $remote) {
    $resolved = poc_resolve($remote);
    list($changed, $last_change) = poc_peer_state($scope, $id, $remote, $resolved);
    $ping = poc_ping($resolved);

    return array_merge([
        'version' => POC_VERSION,
        'scope' => $scope,
        'id' => (string)$id,
        'name' => (string)$name,
        'remote_gateway' => (string)$remote,
        'resolved_ip' => (string)$resolved,
        'peer_changed' => $changed,
        'last_change_epoch' => $last_change
    ], $ping);
}

function poc_discovery_ipsec() {
    global $config;
    init_config_arr(['ipsec', 'phase1']);
    $rows = [];

    foreach ($config['ipsec']['phase1'] as $data) {
        $rows[] = [
            '{#IKEID}' => isset($data['ikeid']) ? (string)$data['ikeid'] : '',
            '{#NAME}' => isset($data['descr']) ? (string)$data['descr'] : '',
            '{#REMOTE}' => isset($data['remote-gateway']) ? (string)$data['remote-gateway'] : ''
        ];
    }

    poc_json(['data' => $rows]);
}

function poc_probe_ipsec($ikeid) {
    global $config;
    init_config_arr(['ipsec', 'phase1']);

    $name = '';
    $remote = '';

    foreach ($config['ipsec']['phase1'] as $data) {
        if (isset($data['ikeid']) && (string)$data['ikeid'] === (string)$ikeid) {
            $name = isset($data['descr']) ? (string)$data['descr'] : '';
            $remote = isset($data['remote-gateway']) ? trim((string)$data['remote-gateway']) : '';
            break;
        }
    }

    $probe = array_merge(
        poc_base_probe('ipsec', $ikeid, $name, $remote),
        poc_ipsec_runtime($ikeid),
        ['vpn_type' => 'ipsec', 'unit_name' => $name]
    );
    if ($remote === '') {
        $probe['error'] = 'phase1_not_found_or_remote_empty';
    }
    poc_json($probe);
}


function poc_first_value($data, $keys, $default=null) {
    if (!is_array($data)) {
        return $default;
    }
    foreach ($keys as $key) {
        if (array_key_exists($key, $data) && $data[$key] !== '' && $data[$key] !== null) {
            return $data[$key];
        }
    }
    return $default;
}

function poc_numeric_or_null($value) {
    return is_numeric($value) ? 0 + $value : null;
}

function poc_find_recursive($data, $keys) {
    if (!is_array($data)) {
        return null;
    }

    foreach ($keys as $key) {
        if (array_key_exists($key, $data) && $data[$key] !== '' && $data[$key] !== null) {
            return $data[$key];
        }
    }

    foreach ($data as $value) {
        if (is_array($value)) {
            $found = poc_find_recursive($value, $keys);
            if ($found !== null) {
                return $found;
            }
        }
    }
    return null;
}

/*
 * Runtime OpenVPN client:
 * usa somente os campos que o pfSense efetivamente devolver.
 * Campos ausentes permanecem null, nunca são inventados como zero.
 */
function poc_openvpn_runtime($vpnid) {
    $result = [
        'runtime_found' => 0,
        'status' => null,
        'connected_since_epoch' => null,
        'uptime_sec' => null,
        'bytes_in' => null,
        'bytes_out' => null,
        'remote_host_runtime' => '',
        'virtual_addr' => ''
    ];

    $clients = openvpn_get_active_clients();
    foreach ($clients as $client) {
        if (!isset($client['vpnid']) || (string)$client['vpnid'] !== (string)$vpnid) {
            continue;
        }

        $result['runtime_found'] = 1;
        $result['status'] = poc_first_value($client, ['status', 'state'], null);

        $connected = poc_numeric_or_null(poc_first_value(
            $client,
            ['connect_time_unix', 'connected_since', 'start_time', 'time_unix'],
            null
        ));
        $result['connected_since_epoch'] = $connected;
        if ($connected !== null && $connected > 0 && $connected <= time()) {
            $result['uptime_sec'] = time() - (int)$connected;
        }

        $result['bytes_in'] = poc_numeric_or_null(poc_first_value(
            $client,
            ['bytes_recv', 'bytes_received', 'bytes_in', 'received_bytes'],
            null
        ));
        $result['bytes_out'] = poc_numeric_or_null(poc_first_value(
            $client,
            ['bytes_sent', 'bytes_out', 'sent_bytes'],
            null
        ));

        $result['remote_host_runtime'] = (string)poc_first_value(
            $client,
            ['remote_host', 'remote_addr', 'server_addr'],
            ''
        );
        $result['virtual_addr'] = (string)poc_first_value(
            $client,
            ['virtual_addr', 'virtual_address', 'ifconfig_pool_remote_ip'],
            ''
        );
        break;
    }

    return $result;
}

/*
 * Runtime IPsec:
 * ipsec_list_sa() mudou de estrutura entre releases do pfSense/strongSwan.
 * A POC procura apenas chaves conhecidas de forma defensiva.
 * Se não houver correspondência confiável, retorna null em bytes/uptime.
 */
function poc_ipsec_runtime($ikeid) {
    $result = [
        'runtime_found' => 0,
        'status' => null,
        'connected_since_epoch' => null,
        'uptime_sec' => null,
        'bytes_in' => null,
        'bytes_out' => null
    ];

    $sas = ipsec_list_sa();
    if (!is_array($sas)) {
        return $result;
    }

    $candidates = [];
    foreach ($sas as $key => $sa) {
        if (!is_array($sa)) {
            continue;
        }

        $serialized = json_encode($sa);
        $match = false;

        if (isset($sa['ikeid']) && (string)$sa['ikeid'] === (string)$ikeid) {
            $match = true;
        }
        if (!$match && isset($sa['con-id'])) {
            $digits = preg_replace('/\D+/', '', (string)$sa['con-id']);
            if ($digits !== '' && strpos($digits, (string)$ikeid) === 0) {
                $match = true;
            }
        }
        if (!$match && is_string($key) && preg_match('/(^|[^0-9])'.preg_quote((string)$ikeid, '/').'([^0-9]|$)/', $key)) {
            $match = true;
        }
        if (!$match && is_string($serialized) && preg_match('/"ikeid"\s*:\s*"?'.preg_quote((string)$ikeid, '/').'"?/', $serialized)) {
            $match = true;
        }

        if ($match) {
            $candidates[] = $sa;
        }
    }

    if (!$candidates) {
        return $result;
    }

    $result['runtime_found'] = 1;
    $result['status'] = 1;

    $bytes_in = 0;
    $bytes_out = 0;
    $have_in = false;
    $have_out = false;
    $oldest = null;

    foreach ($candidates as $sa) {
        $vin = poc_find_recursive($sa, [
            'bytes-in', 'bytes_in', 'bytes_recv', 'bytes_received', 'inBytes', 'rx_bytes'
        ]);
        $vout = poc_find_recursive($sa, [
            'bytes-out', 'bytes_out', 'bytes_sent', 'outBytes', 'tx_bytes'
        ]);

        if (is_numeric($vin)) {
            $bytes_in += 0 + $vin;
            $have_in = true;
        }
        if (is_numeric($vout)) {
            $bytes_out += 0 + $vout;
            $have_out = true;
        }

        $since = poc_find_recursive($sa, [
            'connected_since', 'install-time', 'install_time', 'established', 'start_time', 'time_unix'
        ]);
        if (is_numeric($since)) {
            $since = (int)$since;
            if ($since > 0 && $since <= time() && ($oldest === null || $since < $oldest)) {
                $oldest = $since;
            }
        }
    }

    if ($have_in) {
        $result['bytes_in'] = $bytes_in;
    }
    if ($have_out) {
        $result['bytes_out'] = $bytes_out;
    }
    if ($oldest !== null) {
        $result['connected_since_epoch'] = $oldest;
        $result['uptime_sec'] = time() - $oldest;
    }

    return $result;
}

function poc_debug_ipsec_runtime($ikeid='') {
    $sas = ipsec_list_sa();
    if ($ikeid === '') {
        poc_json($sas);
        return;
    }

    $matches = [];
    if (is_array($sas)) {
        foreach ($sas as $key => $sa) {
            if (!is_array($sa)) continue;
            $serialized = json_encode($sa);
            if (
                (isset($sa['ikeid']) && (string)$sa['ikeid'] === (string)$ikeid) ||
                (is_string($serialized) && preg_match('/"ikeid"\s*:\s*"?'.preg_quote((string)$ikeid, '/').'"?/', $serialized))
            ) {
                $matches[$key] = $sa;
            }
        }
    }
    poc_json($matches);
}

function poc_debug_openvpn_runtime($vpnid='') {
    $clients = openvpn_get_active_clients();
    if ($vpnid === '') {
        poc_json($clients);
        return;
    }
    $matches = [];
    foreach ($clients as $client) {
        if (isset($client['vpnid']) && (string)$client['vpnid'] === (string)$vpnid) {
            $matches[] = $client;
        }
    }
    poc_json($matches);
}

function poc_openvpn_clients_config() {
    global $config;
    init_config_arr(['openvpn', 'openvpn-client']);
    return isset($config['openvpn']['openvpn-client']) && is_array($config['openvpn']['openvpn-client'])
        ? $config['openvpn']['openvpn-client']
        : [];
}

function poc_discovery_openvpn_client() {
    $rows = [];

    foreach (poc_openvpn_clients_config() as $data) {
        $vpnid = isset($data['vpnid']) ? (string)$data['vpnid'] : '';
        if ($vpnid === '') {
            continue;
        }

        $name = '';
        foreach (['description', 'descr'] as $field) {
            if (isset($data[$field]) && trim((string)$data[$field]) !== '') {
                $name = (string)$data[$field];
                break;
            }
        }

        $remote = isset($data['server_addr']) ? (string)$data['server_addr'] : '';

        $rows[] = [
            '{#VPNID}' => $vpnid,
            '{#NAME}' => $name,
            '{#REMOTE}' => $remote
        ];
    }

    poc_json(['data' => $rows]);
}

function poc_probe_openvpn_client($vpnid) {
    $name = '';
    $remote = '';

    foreach (poc_openvpn_clients_config() as $data) {
        if (isset($data['vpnid']) && (string)$data['vpnid'] === (string)$vpnid) {
            foreach (['description', 'descr'] as $field) {
                if (isset($data[$field]) && trim((string)$data[$field]) !== '') {
                    $name = (string)$data[$field];
                    break;
                }
            }
            $remote = isset($data['server_addr']) ? trim((string)$data['server_addr']) : '';
            break;
        }
    }

    $probe = array_merge(
        poc_base_probe('openvpn_client', $vpnid, $name, $remote),
        poc_openvpn_runtime($vpnid),
        ['vpn_type' => 'openvpn_client', 'unit_name' => $name]
    );
    if ($remote === '') {
        $probe['error'] = 'openvpn_client_not_found_or_remote_empty';
    }
    poc_json($probe);
}

$cmd = isset($argv[1]) ? strtolower($argv[1]) : '';

switch ($cmd) {
    case 'discovery_ipsec':
        poc_discovery_ipsec();
        break;

    case 'probe_ipsec':
        poc_probe_ipsec(isset($argv[2]) ? $argv[2] : '');
        break;

    case 'discovery_openvpn_client':
        poc_discovery_openvpn_client();
        break;

    case 'probe_openvpn_client':
        poc_probe_openvpn_client(isset($argv[2]) ? $argv[2] : '');
        break;

    case 'debug_ipsec_runtime':
        poc_debug_ipsec_runtime(isset($argv[2]) ? $argv[2] : '');
        break;

    case 'debug_openvpn_runtime':
        poc_debug_openvpn_runtime(isset($argv[2]) ? $argv[2] : '');
        break;

    case 'version':
        echo POC_VERSION;
        break;

    default:
        poc_json([
            'version' => POC_VERSION,
            'error' => 'invalid_command'
        ]);
        break;
}
