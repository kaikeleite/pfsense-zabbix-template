<?php
/*** 
pfsense_zbx.php - pfSense Zabbix Interface
Version 0.24.7 - 2024-04-27

Written by Riccardo Bicelli <r.bicelli@gmail.com>
This program is licensed under Apache 2.0 License
*/

//Some Useful defines
define ('SCRIPT_VERSION','0.24.7-baitz.5');

define('SPEEDTEST_INTERVAL', 8); //Speedtest Interval (in hours)
define('CRON_TIME_LIMIT', 300); // Time limit in seconds of speedtest and sysinfo 
define('DEFAULT_TIME_LIMIT', 30); // Time limit in seconds otherwise

/*
 * Tráfego filtrado (Grafana/Zabbix) — só rede do CLIENTE nos gráficos.
 *
 * Modo frota (150+ pfSense): filtragem por IP/CIDR em PFZ_TRAFFIC_EXCLUDE_NETS.
 * NÃO depende de nome de regra, alias ou Description — mesmo script em todos.
 * Lê states do PF (por hwif), acumula deltas em /tmp e devolve contador cumulativo.
 * Ver: pfsense_traffic_filtered_SETUP.md
 */
define('PFZ_TRAFFIC_EXCLUDE_LABEL', 'zbx_excl'); // opcional; só se PFZ_TRAFFIC_USE_LABELS=true
define('PFZ_TRAFFIC_BACKUP_LABEL', 'zbx_excl');
define('PFZ_TRAFFIC_USE_LABELS', false); // true = soma labels zbx_excl além do CIDR (opcional)
define('PFZ_TRAFFIC_STATE_CACHE_TTL', 20); // segundos: evita pfctl repetido no mesmo poll Zabbix
define('PFZ_TRAFFIC_STATE_FILE', '/tmp/pfz_traffic_excl_state.json');
/*
 * Redes/hosts Baitz (gerência) — lista ÚNICA para todos os clientes.
 * Espelha aliases típicos: IP_NETWORK, Bacula_*, IP_NOC, IP_BAITZ_*, VPN SSL.
 * Qualquer state com src ou dst nestes IPs/CIDRs entra em "excluded" da iface do state.
 * NÃO usar 10.0.0.0/16 — WAN do cliente pode viver nesse /16 (só /24s de gerência).
 */
define('PFZ_TRAFFIC_EXCLUDE_NETS',
	/* Bacula_DS */
	'10.3.0.127,' .
	'10.0.0.230,' .
	'10.0.0.232,' .
	/* Bacula_Dir */
	'10.3.0.126,' .
	'10.3.0.247,' .
	/* IP_BAITZ_GUACAMOLE / IP_DC_BACKUP (fora só dos /24 abaixo) */
	'10.3.0.101,' .
	'10.3.0.40,' .
	/* IP_NETWORK (gerência Baitz) */
	'10.0.0.0/24,' .
	'10.0.2.0/24,' .
	'10.0.3.0/24,' .
	'10.0.4.0/24,' .
	'10.0.5.0/24,' .
	'172.16.0.0/16,' .
	'172.17.0.0/16,' .
	'172.18.0.0/16,' .
	/* IPs_Baitz_VPN / Network_VPN_SSL */
	'10.98.102.0/24,' .
	'10.98.103.0/24'
);

require_once('globals.inc');
require_once('functions.inc');
require_once('config.inc');
require_once('util.inc');

//For Interfaces Discovery
require_once('interfaces.inc');

//For OpenVPN Discovery
require_once('openvpn.inc');

//For Service Discovery
require_once("service-utils.inc");

//For System
require_once('pkg-utils.inc'); 

//For DHCP

//Backporting php 8 functions
if (!function_exists('str_contains')){

	function str_contains($haystack,$needle){

		return strstr($haystack,$needle);
	}

}

//pfSense 2.7-2.8 Compatibility
if (!function_exists('get_drive_list')){

	function get_drive_list() {

		get_smart_drive_list();

	}

}

//Testing function, for template creating purpose
function pfz_test(){
        $line = "-------------------\n";
        
        $ovpn_servers = pfz_openvpn_get_all_servers();
        echo "OPENVPN Servers:\n";
        print_r($ovpn_servers);
        echo $line;

        $ovpn_clients = openvpn_get_active_clients();
        echo "OPENVPN Clients:\n";
        print_r($ovpn_clients);
        echo $line;

        $ifdescrs = get_configured_interface_with_descr(true);
        $ifaces=array();
        foreach ($ifdescrs as $ifdescr => $ifname){	     
          $ifinfo = get_interface_info($ifdescr);
          $ifaces[$ifname] = $ifinfo;
        }
        echo "Network Interfaces:\n";        
        print_r($ifaces);
        print_r(get_interface_arr());
        print_r(get_configured_interface_list());
        echo $line;

        $services = get_services();
        echo "Services: \n";
        print_r($services);
        echo $line;
        
        echo "IPsec: \n";
	
		require_once("ipsec.inc");
		global $config;
		init_config_arr(array('ipsec', 'phase1'));
		init_config_arr(array('ipsec', 'phase2'));
		$a_phase2 = &$config['ipsec']['phase2'];
        $status = ipsec_list_sa();
		echo "IPsec Status: \n";
		print_r($status);		
		
		$a_phase1 = &$config['ipsec']['phase1'];
		$a_phase2 = &$config['ipsec']['phase2'];
	
		echo "IPsec Config Phase 1: \n";
		print_r($a_phase1);
		
		echo "IPsec Config Phase 2: \n";
		print_r($a_phase2);
		
		echo $line;
		
		//Packages
		echo "Packages: \n";
		require_once("pkg-utils.inc");
		$installed_packages = get_pkg_info('all', false, true);
		print_r($installed_packages);
}


// Interface Discovery
// Improved performance
function pfz_interface_discovery($is_wan=false,$is_cron=false) {
    $ifdescrs = get_configured_interface_with_descr(true);
    $ifaces = get_interface_arr();
    $ifcs=array();
    $if_ret=array();
 
    $json_string = '{"data":[';
                   
    foreach ($ifdescrs as $ifname => $ifdescr){
          $ifinfo = get_interface_info($ifname);
          $ifinfo["description"] = $ifdescr;
	      $ifcs[$ifname] = $ifinfo;	      
    }    

    foreach ($ifaces as $hwif) {
        
        $ifdescr = $hwif;
        $has_gw = false;
        $is_vpn = false;
        $has_public_ip = false;
        
        foreach($ifcs as $ifc=>$ifinfo){
                if ($ifinfo["hwif"] == $hwif){
                        $ifdescr = $ifinfo["description"];
                        if (array_key_exists("gateway",$ifinfo)) $has_gw=true;
                        //	Issue #81 - https://stackoverflow.com/a/13818647/15093007
                        if (filter_var($ifinfo["ipaddr"], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) $has_public_ip=true;
                        if (strpos($ifinfo["if"],"ovpn")!==false) $is_vpn=true;
                        break;
                }
        }
		
		if ( ($is_wan==false) ||  (($is_wan==true) && (($has_gw==true) || ($has_public_ip==true)) && ($is_vpn==false)) ) { 
		    $if_ret[]=$hwif;
		    $json_string .= '{"{#IFNAME}":"' . $hwif . '"';
		    $json_string .= ',"{#IFDESCR}":"' . $ifdescr . '"';
		    $json_string .= '},';
        }
    
    }
    $json_string = rtrim($json_string,",");
    $json_string .= "]}";

	if ($is_cron) return $if_ret;
	
    echo $json_string;
}


//Interface Speedtest
function pfz_interface_speedtest_value($ifname, $value){	
    $tvalue = explode(".", $value);    
    
    if (count($tvalue)>1) {
    	$value = $tvalue[0];
    	$subvalue = $tvalue[1];
    }        
    
	//If the interface has a gateway is considered WAN, so let's do the speedtest
	$filename = "/tmp/speedtest-$ifname";
	
	if (file_exists($filename)) {
		$speedtest_data = json_decode(file_get_contents($filename), true) ?? [];
		
		if (array_key_exists($value, $speedtest_data)) {
			if ($subvalue == false) 
				echo $speedtest_data[$value];
			else
				echo $speedtest_data[$value][$subvalue];
		}	
	}
			
}

// This is supposed to run via cron job
function pfz_speedtest_cron(){
	require_once("services.inc");
	$ifdescrs = get_configured_interface_with_descr(true);
    $ifaces = get_interface_arr();
    $pf_interface_name='';
    $subvalue=false;    
		                       
    $ifcs = pfz_interface_discovery(true, true);    
    
    foreach ($ifcs as $ifname) {
          foreach ($ifdescrs as $ifn => $ifd){
		      $ifinfo = get_interface_info($ifn);
		      if($ifinfo['hwif']==$ifname) {
		      	$pf_interface_name = $ifn;
		      	break;
		      }
    	  }	
		  pfz_speedtest_exec($ifname, $ifinfo['ipaddr']);
    }
}

//installs a cron job for speedtests
function pfz_speedtest_cron_install($enable=true){
	//Install Cron Job
	$command = "/usr/local/bin/php " . __FILE__ . " speedtest_cron";
	install_cron_job($command, $enable, $minute = "*/15", "*", "*", "*", "*", "root", true);
}        	


// 2023-02-26:
// Fixed issue #127
function pfz_speedtest_exec ($ifname, $ipaddr){
	
	$filename = "/tmp/speedtest-$ifname";
	$filetemp = "$filename.tmp";
	$filerun = "/tmp/speedtest-run"; 
	
	// Issue #82
	// Sleep random delay in order to avoid problem when 2 pfSense on the same Internet line
	sleep (rand ( 1, 90));
	
	if ( (time()-filemtime($filename) > SPEEDTEST_INTERVAL * 3600) || (file_exists($filename)==false) ) {
	  	// file is older than SPEEDTEST_INTERVAL
	  	if ( (time()-filemtime($filerun) > 180 ) ) @unlink($filerun);

		if (file_exists($filerun)==false) {	  			  		
	  		touch($filerun);
	  		$st_command = "/usr/local/bin/speedtest --secure --source $ipaddr --json > $filetemp";
			exec ($st_command);
			rename($filetemp,$filename);
			@unlink($filerun);
		}
	}	
	
	return true;
}


// OpenVPN Server Discovery
function pfz_openvpn_get_all_servers(){
     $servers = openvpn_get_active_servers();
     $sk_servers = openvpn_get_active_servers("p2p");
     $servers = array_merge($servers,$sk_servers);
     return ($servers);
}


function pfz_openvpn_serverdiscovery() {
     $servers = pfz_openvpn_get_all_servers();

     $json_string = '{"data":[';

     foreach ($servers as $server){
          $name = trim(preg_replace('/\w{3}(\d)?\:\d{4,5}/i', '', $server['name']));
          $json_string .= '{"{#SERVER}":"' . $server['vpnid'] . '"';
          $json_string .= ',"{#NAME}":"' . $name . '"';  
          $json_string .= '},';
     }

     $json_string = rtrim($json_string,",");
     $json_string .= "]}";

     echo $json_string;
}


// Get OpenVPN Server Value
function pfz_openvpn_servervalue($server_id,$valuekey){
     $servers = pfz_openvpn_get_all_servers();     
     
     foreach($servers as $server) {
          if($server['vpnid']==$server_id){
               $value = $server[$valuekey];
               if ($valuekey=="status") {
                    if ( ($server['mode']=="server_user") || ($server['mode']=="server_tls_user") || ($server['mode']=="server_tls") ){
                         if ($value=="") $value="server_user_listening";                    
                    } else if ($server['mode']=="p2p_tls"){
                        // For p2p_tls, ensure we have one client, and return up if it's the case
                        if ($value=="")
                            $value=(is_array($server["conns"]) && count($server["conns"]) > 0) ? "up" : "down";
                    }                  
               }
          }
     }
     
     switch ($valuekey){     
          
          case "conns":
               //Client Connections: is an array so it is sufficient to count elements                    
               if (is_array($value))
                    $value = count($value);
               else
                    $value = "0";
               break;     
               
          case "status":
               
               $value = pfz_valuemap("openvpn.server.status", $value);
               break;

          case "mode":
               $value = pfz_valuemap("openvpn.server.mode", $value);
               break;
     }
     
     //if ($value=="") $value="none";
     echo $value;
}

//OpenVPN Server/User-Auth Discovery
function pfz_openvpn_server_userdiscovery(){
     $servers = pfz_openvpn_get_all_servers();

     $json_string = '{"data":[';

     foreach ($servers as $server){
          if ( ($server['mode']=='server_user') || ($server['mode']=='server_tls_user') || ($server['mode']=='server_tls') ) {
               if (is_array($server['conns'])) {               
                    $name = trim(preg_replace('/\w{3}(\d)?\:\d{4,5}/i', '', $server['name']));
                    
                    foreach($server['conns'] as $conn) {
                    	
                    	$common_name = pfz_replacespecialchars($conn['common_name']);
                    	               
                        $json_string .= '{"{#SERVERID}":"' . $server['vpnid'] . '"';
                        $json_string .= ',"{#SERVERNAME}":"' . $name . '"';
                        $json_string .= ',"{#UNIQUEID}":"' . $server['vpnid'] . '+' . $common_name . '"';                         
                        $json_string .= ',"{#USERID}":"' . $conn['common_name'] . '"';    
                        $json_string .= '},';
                    }
               }
          }
     }

     $json_string = rtrim($json_string,",");
     $json_string .= "]}";

     echo $json_string;
}

// Get OpenVPN User Connected Value
function pfz_openvpn_server_uservalue($unique_id, $valuekey, $default=""){

	 $unique_id = pfz_replacespecialchars($unique_id,true);
     $atpos=strpos($unique_id,'+');
     $server_id = substr($unique_id,0,$atpos);
     $user_id = substr($unique_id,$atpos+1);
     
     $servers = pfz_openvpn_get_all_servers();
     foreach($servers as $server) {
          if($server['vpnid']==$server_id) {
               foreach($server['conns'] as $conn) {               
                    if ($conn['common_name']==$user_id){
                         $value = $conn[$valuekey];
                    }
               }               
          }
     }
     if ($value=="") $value = $default;
     echo $value;
}
// OpenVPN Client Discovery
function pfz_openvpn_clientdiscovery() {
     $clients = openvpn_get_active_clients();

     $json_string = '{"data":[';

     foreach ($clients as $client){
          $name = trim(preg_replace('/\w{3}(\d)?\:\d{4,5}/i', '', $client['name']));
          $json_string .= '{"{#CLIENT}":"' . $client['vpnid'] . '"';
          $json_string .= ',"{#NAME}":"' . $name . '"';
          $json_string .= '},';
     }

     $json_string = rtrim($json_string,",");
     $json_string .= "]}";

     echo $json_string;
}

function pfz_replacespecialchars($inputstr,$reverse=false){
	 $specialchars = ",',\",`,*,?,[,],{,},~,$,!,&,;,(,),<,>,|,#,@,0x0a";
	 $specialchars = explode(",",$specialchars);	 
	 $resultstr = $inputstr;
	 
	 for ($n=0;$n<count($specialchars);$n++){
	 	if ($reverse==false)
	 		$resultstr = str_replace($specialchars[$n],'%%' . $n . '%',$resultstr);
	 	else
	 		$resultstr = str_replace('%%' . $n . '%',$specialchars[$n],$resultstr);
	 }	 
	 
	 return ($resultstr);
}

function pfz_openvpn_clientvalue($client_id, $valuekey, $default="none"){
     $clients = openvpn_get_active_clients();     
     foreach($clients as $client) {
          if($client['vpnid']==$client_id)
               $value = $client[$valuekey];
     }

     switch ($valuekey){        
               
          case "status":
               $value = pfz_valuemap("openvpn.client.status", $value);
               break;

     }

     if ($value=="") $value=$default;
     echo $value;
}


// Services Discovery
// 2020-03-27: Added space replace with __ for issue #12
function pfz_services_discovery(){
     $services = get_services();

     $json_string = '{"data":[';

     foreach ($services as $service){
          if (!empty($service['name'])) {
               
               $status = get_service_status($service);
               if ($status="") $status = 0;

               $id="";               
               //id for OpenVPN               
               if (!empty($service['id'])) $id = "." . $service["id"];
               //zone for Captive Portal
               if (!empty($service['zone'])) $id = "." . $service["zone"];
                              
               $json_string .= '{"{#SERVICE}":"' . str_replace(" ", "__", $service['name']) . $id . '"';          
               $json_string .= ',"{#DESCRIPTION}":"' . $service['description'] . '"';
               $json_string .= '},';
          }
     }     
     $json_string = rtrim($json_string,",");
     $json_string .= "]}";
     
     echo $json_string;

}

// Get service value
// 2020-03-27: Added space replace in service name for issue #12
// 2020-09-28: Corrected Space Replace
function pfz_service_value($name,$value){
     $services = get_services();     
     $name = str_replace("__"," ",$name);
           
     //List of service which are stopped on CARP Slave.
     //For now this is the best way i found for filtering out the triggers
     //Waiting for a way in Zabbix to use Global Regexp in triggers with items discovery
     $stopped_on_carp_slave = array("haproxy","radvd","openvpn.","openvpn","avahi");
     
     foreach ($services as $service){
          $namecfr = $service["name"];
          $carpcfr = $service["name"];          

          //OpenVPN          
          if (!empty($service['id'])) {                           
               $namecfr = $service['name'] . "." . $service["id"];
               $carpcfr = $service['name'] . ".";          
          }

          //Captive Portal
          if (!empty($service['zone'])) {                           
               $namecfr = $service['name'] . "." . $service["zone"];
               $carpcfr = $service['name'] . ".";          
          }          

          if ($namecfr == $name){
               switch ($value) {
               
                    case "status":
                         $status = get_service_status($service);
                         if ($status=="") $status = 0;
                         echo $status;
                         return;

                    case "name":
                         echo $namecfr;
                         return;

                    case "enabled":
                         if (is_service_enabled($service['name']))
                              echo 1;
                         else
                              echo 0;
                         return;

                    case "run_on_carp_slave":
                         if (in_array($carpcfr,$stopped_on_carp_slave))
                              echo 0;
                         else
                              echo 1;
                         return;
                    default:               
                         echo $service[$value];
                         return;
               }
          }                                              
    }

    echo 0;
}


//Gateway Discovery
function pfz_gw_rawstatus() {
     // Return a Raw Gateway Status, useful for action Scripts (e.g. Update Cloudflare DNS config)
     $gws = return_gateways_status(true);
     $gw_string="";
     foreach ($gws as $gw){
          $gw_string .= ($gw['name'] . '.' . $gw['status'] .",");
     }
     echo rtrim($gw_string,",");
}


function pfz_gw_discovery() {
     $gws = return_gateways_status(true);

     $json_string = '{"data":[';
     foreach ($gws as $gw){          
          $json_string .= '{"{#GATEWAY}":"' . $gw['name'] . '"';          
          $json_string .= '},';
     }     
     $json_string = rtrim($json_string,",");
     $json_string .= "]}";
     
     echo $json_string;
}


function pfz_gw_value($gw, $valuekey) {
     $gws = return_gateways_status(true);
     if(array_key_exists($gw,$gws)) {
          $value = $gws[$gw][$valuekey];
          if ($valuekey=="status") { 
               //Issue #70: Gateway Forced Down
               //Issue #182: Gateway not marked as Down
               if (($gws[$gw]["status"]=="force_down") && ($gws[$gw]["substatus"]<>"none")) 
                    $value = $gws[$gw]["substatus"];
               
               $value = pfz_valuemap("gateway.status", $value);
          }     
          echo $value;         
     }
}


// IPSEC Discovery
function pfz_ipsec_discovery_ph1(){
	
	require_once("ipsec.inc");	
	global $config;
	init_config_arr(array('ipsec', 'phase1'));
	$a_phase1 = &$config['ipsec']['phase1'];
	
	$json_string = '{"data":[';
	
	foreach ($a_phase1 as $data) {
		$json_string .= '{"{#IKEID}":"' . $data['ikeid'] . '"';
		$json_string .= ',"{#NAME}":"' . $data['descr'] . '"';
		$json_string .= '},';
	}	

	$json_string = rtrim($json_string,",");
    $json_string .= "]}";     	
    
    echo $json_string;
	
}

function pfz_ipsec_ph1($ikeid,$valuekey){	
	// Get Value from IPsec Phase 1 Configuration
	// If Getting "disabled" value only check item presence in config array

	require_once("ipsec.inc");
	global $config;
	init_config_arr(array('ipsec', 'phase1'));
	$a_phase1 = &$config['ipsec']['phase1'];	

	$value = "";	
	switch ($valuekey) {
		case 'status':
			$value = pfz_ipsec_status($ikeid);
			break;
		case 'disabled':
			$value = "0";		
		default:
			foreach ($a_phase1 as $data) {
				if ($data['ikeid'] == $ikeid) {
					if(array_key_exists($valuekey,$data)) {
					if ($valuekey=='disabled')
						$value = "1";
					else
						$value = pfz_valuemap("ipsec." . $valuekey, $data[$valuekey], $data[$valuekey]);
					break;
					}
				}
			}		
	}
	echo $value;
}

function pfz_ipsec_discovery_ph2(){
	
	require_once("ipsec.inc");
	
	global $config;
	init_config_arr(array('ipsec', 'phase2'));
	$a_phase2 = &$config['ipsec']['phase2'];
	
	$json_string = '{"data":[';
	
	foreach ($a_phase2 as $data) {
		$json_string .= '{"{#IKEID}":"' . $data['ikeid'] . '"';
		$json_string .= ',"{#NAME}":"' .  $data['descr'] . '"';
		$json_string .= ',"{#UNIQID}":"' .  $data['uniqid'] . '"';
		$json_string .= ',"{#REQID}":"' .  $data['reqid'] . '"';
		$json_string .= ',"{#EXTID}":"' .  $data['ikeid'] . '.' . $data['reqid'] . '"';
		$json_string .= '},';
	}	

	$json_string = rtrim($json_string,",");
    $json_string .= "]}";     	
    
    echo $json_string;
	
}

function pfz_ipsec_ph2($uniqid, $valuekey){
	require_once("ipsec.inc");
	global $config;
	init_config_arr(array('ipsec', 'phase2'));
	$a_phase2 = &$config['ipsec']['phase2'];	
	
	$valuecfr = explode(".",$valuekey);
		
	switch ($valuecfr[0]) {
		case 'status':
			$idarr = explode(".", $uniqid);
			$statuskey = "state";
			if (isset($valuecfr[1])) $statuskey = $valuecfr[1]; 
			$value = pfz_ipsec_status($idarr[0],$idarr[1],$statuskey);
			break;
		case 'disabled':
			$value = "0";
	}							
	
	foreach ($a_phase2 as $data) {
		if ($data['uniqid'] == $uniqid) {
			if(array_key_exists($valuekey,$data)) {
			if ($valuekey=='disabled')
				$value = "1";
			else
				$value = pfz_valuemap("ipsec_ph2." . $valuekey, $data[$valuekey], $data[$valuekey]);
			break;
			}
		}
	}
	echo $value;
}

function pfz_ipsec_status($ikeid,$reqid=-1,$valuekey='state'){
		
	require_once("ipsec.inc");
	global $config;
	init_config_arr(array('ipsec', 'phase1'));
	
	$a_phase1 = &$config['ipsec']['phase1'];
	$conmap = array();
	foreach ($a_phase1 as $ph1ent) {
	    if (function_exists('get_ipsecifnum')) {
            if (get_ipsecifnum($ph1ent['ikeid'], 0)) {
                $cname = "con" . get_ipsecifnum($ph1ent['ikeid'], 0);
            } else {
                $cname = "con{$ph1ent['ikeid']}00000";
            }
        } else{
            $cname = ipsec_conid($ph1ent);
        }
        
        $conmap[$cname] = $ph1ent['ikeid'];
    }

	$status = ipsec_list_sa();
	$ipsecconnected = array();
	
	$carp_status = pfz_carp_status(false);
	
	//Phase-Status match borrowed from status_ipsec.php	
	if (is_array($status)) {		
		foreach ($status as $l_ikeid=>$ikesa) {
			
			if (isset($ikesa['con-id'])) {
				$con_id = substr($ikesa['con-id'], 3);
			} else {
				$con_id = filter_var($ikeid, FILTER_SANITIZE_NUMBER_INT);
			}
			$con_name = "con" . $con_id;
			if ($ikesa['version'] == 1) {
				$ph1idx = $conmap[$con_name];
				$ipsecconnected[$ph1idx] = $ph1idx;
			} else {
				if (!ipsec_ikeid_used($con_id)) {
					// probably a v2 with split connection then
					$ph1idx = $conmap[$con_name];
					$ipsecconnected[$ph1idx] = $ph1idx;
				} else {
					$ipsecconnected[$con_id] = $ph1idx = $con_id;
				}
			}
			if ($ph1idx == $ikeid){
				if ($reqid!=-1) {
					// Asking for Phase2 Status Value
					foreach ($ikesa['child-sas'] as $childsas) {
						if ($childsas['reqid']==$reqid) {
							if (strtolower($childsas['state']) == 'rekeyed') {
								//if state is rekeyed go on
								$tmp_value = $childsas[$valuekey];
							} else {
								$tmp_value = $childsas[$valuekey];
								break;
							}
						}						
					}
				} else {
					$tmp_value = $ikesa[$valuekey];
				}
								
				break;
			}			
		}	
	}
	
	switch($valuekey) {
					case 'state':
						$value = pfz_valuemap('ipsec.state', strtolower($tmp_value));
						if ($carp_status!=0) $value = $value + (10 * ($carp_status-1));						
						break;
					default:
						$value = $tmp_value;
						break;
	}
	
	return $value;
}

// Temperature sensors Discovery
function pfz_temperature_sensors_discovery(){


	$json_string = '{"data":[';
	$sensors = [];
	exec("sysctl -a | grep temperature | cut -d ':' -f 1", $sensors, $code);
	if ($code != 0) {
	    echo "";
	    return;
	} else {
        foreach ($sensors as $sensor) {
            $json_string .= '{"{#SENSORID}":"' . $sensor . '"';
            $json_string .= '},';
        }
    }

	$json_string = rtrim($json_string,",");
    $json_string .= "]}";

    echo $json_string;

}

// Temperature sensor get value
function pfz_get_temperature($sensorid){

	exec("sysctl '$sensorid' | cut -d ':' -f 2", $value, $code);
	if ($code != 0 or count($value)!=1) {
	    echo "";
	    return;
	} else {
	    echo trim($value[0]);
    }

}


function pfz_carp_status($echo = true){
     //Detect CARP Status
     global $config;
     $status_return = 0;
     $status = get_carp_status();
     $carp_detected_problems = get_single_sysctl("net.inet.carp.demotion");

	 //CARP is disabled
	 $ret = 0;
	 
     if ($status != 0) { //CARP is enabled

          if ($carp_detected_problems != 0) {                              
			   //There's some Major Problems with CARP
               $ret = 4;
               if ($echo == true) echo $ret;   
               return $ret;
          }
                    
          $status_changed = false;
          $prev_status = "";
          foreach ($config['virtualip']['vip'] as $carp) {
		     if ($carp['mode'] != "carp") {
			     continue;
		     }
               $if_status = get_carp_interface_status("_vip{$carp['uniqid']}");

               if ( ($prev_status != $if_status) && (empty($if_status)==false) ) { //Some glitches with GUI
                    if ($prev_status!="") $status_changed = true;
                    $prev_status = $if_status;
               }
          }          
          if ($status_changed) {
               //CARP Status is inconsistent across interfaces
               $ret=3;
               echo 3;          
          } else {
               if ($prev_status=="MASTER")
                    $ret = 1;                    
               else
					$ret = 2;
          }      
     }
     
     if ($echo == true) echo $ret;   
     return $ret;
     
}

// DHCP Checks (copy of status_dhcp_leases.php, waiting for pfsense 2.5)
function pfz_remove_duplicate($array, $field) {
	foreach ($array as $sub) {
		$cmp[] = $sub[$field];
	}
	$unique = array_unique(array_reverse($cmp, true));
	foreach ($unique as $k => $rien) {
		$new[] = $array[$k];
	}
	return $new;
}

// Get DHCP Arrays (copied from status_dhcp_leases.php, waiting for pfsense 2.5, in order to use system_get_dhcpleases();)
function pfz_dhcp_get($valuekey) {

	require_once("config.inc");
	
	$leasesfile = "{$g['dhcpd_chroot_path']}/var/db/dhcpd.leases";

	$awk = "/usr/bin/awk";
	/* this pattern sticks comments into a single array item */
	$cleanpattern = "'{ gsub(\"#.*\", \"\");} { gsub(\";\", \"\"); print;}'";
	/* We then split the leases file by } */
	$splitpattern = "'BEGIN { RS=\"}\";} {for (i=1; i<=NF; i++) printf \"%s \", \$i; printf \"}\\n\";}'";

	/* stuff the leases file in a proper format into a array by line */
	@exec("/bin/cat {$leasesfile} 2>/dev/null| {$awk} {$cleanpattern} | {$awk} {$splitpattern}", $leases_content);
	$leases_count = count($leases_content);
	@exec("/usr/sbin/arp -an", $rawdata);

	$leases = [];
	$pools = [];
	
	$i = 0;
	$l = 0;
	$p = 0;

	foreach ($leases_content as $lease) {
		/* split the line by space */
		$data = explode(" ", $lease);
		/* walk the fields */
		$f = 0;
		$fcount = count($data);
		/* with less than 20 fields there is nothing useful */
		if ($fcount < 20) {
			$i++;
			continue;
		}
		while ($f < $fcount) {
			switch ($data[$f]) {
				case "failover":
					$pools[$p]['name'] = trim($data[$f+2], '"');
					$pools[$p]['name'] = "{$pools[$p]['name']} (" . convert_friendly_interface_to_friendly_descr(substr($pools[$p]['name'], 5)) . ")";
					$pools[$p]['mystate'] = $data[$f+7];
					$pools[$p]['peerstate'] = $data[$f+14];
					$pools[$p]['mydate'] = $data[$f+10];
					$pools[$p]['mydate'] .= " " . $data[$f+11];
					$pools[$p]['peerdate'] = $data[$f+17];
					$pools[$p]['peerdate'] .= " " . $data[$f+18];
					$p++;
					$i++;
					continue 3;
				case "lease":
					$leases[$l]['ip'] = $data[$f+1];
					$leases[$l]['type'] = $dynamic_string;
					$f = $f+2;
					break;
				case "starts":
					$leases[$l]['start'] = $data[$f+2];
					$leases[$l]['start'] .= " " . $data[$f+3];
					$f = $f+3;
					break;
				case "ends":
					if ($data[$f+1] == "never") {
						// Quote from dhcpd.leases(5) man page:
						// If a lease will never expire, date is never instead of an actual date.
						$leases[$l]['end'] = gettext("Never");
						$f = $f+1;
					} else {
						$leases[$l]['end'] = $data[$f+2];
						$leases[$l]['end'] .= " " . $data[$f+3];
						$f = $f+3;
					}
					break;
				case "tstp":
					$f = $f+3;
					break;
				case "tsfp":
					$f = $f+3;
					break;
				case "atsfp":
					$f = $f+3;
					break;
				case "cltt":
					$f = $f+3;
					break;
				case "binding":
					switch ($data[$f+2]) {
						case "active":
							$leases[$l]['act'] = $active_string;
							break;
						case "free":
							$leases[$l]['act'] = $expired_string;
							$leases[$l]['online'] = $offline_string;
							break;
						case "backup":
							$leases[$l]['act'] = $reserved_string;
							$leases[$l]['online'] = $offline_string;
							break;
					}
					$f = $f+1;
					break;
				case "next":
					/* skip the next binding statement */
					$f = $f+3;
					break;
				case "rewind":
					/* skip the rewind binding statement */
					$f = $f+3;
					break;
				case "hardware":
					$leases[$l]['mac'] = $data[$f+2];
					/* check if it's online and the lease is active */
					if (in_array($leases[$l]['ip'], $arpdata_ip)) {
						$leases[$l]['online'] = $online_string;
					} else {
						$leases[$l]['online'] = $offline_string;
					}
					$f = $f+2;
					break;
				case "client-hostname":
					if ($data[$f+1] <> "") {
						$leases[$l]['hostname'] = preg_replace('/"/', '', $data[$f+1]);
					} else {
						$hostname = gethostbyaddr($leases[$l]['ip']);
						if ($hostname <> "") {
							$leases[$l]['hostname'] = $hostname;
						}
					}
					$f = $f+1;
					break;
				case "uid":
					$f = $f+1;
					break;
			}
			$f++;
		}
		$l++;
		$i++;
		/* slowly chisel away at the source array */
		array_shift($leases_content);
	}
	/* remove duplicate items by mac address */
	if (count($leases) > 0) {
		$leases = pfz_remove_duplicate($leases, "ip");
	}

	if (count($pools) > 0) {
		$pools = pfz_remove_duplicate($pools, "name");
		asort($pools);
	}

	switch ($valuekey){
		case "pools":
			return $pools;
			break;
		case "failover":
			return $failover;
			break;
		case "leases":
		default:
			return $leases;		
	}

}



function pfz_dhcpfailover_discovery(){
	//System functions regarding DHCP Leases will be available in the upcoming release of pfSense, so let's wait
	require_once("system.inc");
	$leases = system_get_dhcpleases();
	
	$json_string = '{"data":[';
	
	if (count($leases['failover']) > 0){
		foreach ($leases['failover'] as $data){
			   $json_string .= '{"{#FAILOVER_GROUP}":"' . str_replace(" ", "__", $data['name']) . '"';          
		}
	}

	$json_string = rtrim($json_string,",");
    $json_string .= "]}";     	
    
    echo $json_string;
}

function pfz_dhcp_check_failover(){
	// Check DHCP Failover Status
	// Returns number of failover pools which state is not normal or
	// different than peer state
	$failover = pfz_dhcp_get("failover");
	$ret = 0;
	foreach ($failover as $f){
		if ( ($f["mystate"]!="normal") || ($f["mystate"]!=$f["peerstate"])) {
			$ret++;
		}
	}		
	return $ret;	
}

function pfz_dhcp($section, $valuekey=""){
	switch ($section){
		case "failover":
			echo pfz_dhcp_check_failover();
			break;
		default:		
	}
}

//Packages
function pfz_packages_uptodate(){
	require_once("pkg-utils.inc");
	$installed_packages = get_pkg_info('all', false, true);
		
	$ret = 0;

	foreach ($installed_packages as $package){
		if ($package['version']!=$package['installed_version']){
			$ret ++;
		}
	}
	
	return $ret;
}


function pfz_syscheck_cron_install($enable=true){
	//Install Cron Job
	$command = "/usr/local/bin/php " . __FILE__ . " syscheck_cron";
	install_cron_job($command, $enable, $minute = "0", "*/8", "*", "*", "*", "root", true);

	// FIX previous, wrong-coded install command
	$command = "/usr/local/bin/php " . __FILE__ . " systemcheck_cron";
	install_cron_job($command, false, $minute = "0", "9,21", "*", "*", "*", "root", true);
}    

// System information takes a long time to get on slower systems. 
// So it is saved via a cronjob.
function pfz_syscheck_cron (){	
	$filename = "/tmp/sysversion.json";	
	$upToDate = pfz_packages_uptodate();
	$sysVersion = get_system_pkg_version();
	$sysVersion["packages_update"] = $upToDate;
	$sysVersionJson = json_encode($sysVersion);
	if (file_exists($filename)) {
		if ((time()-filemtime($filename) > CRON_TIME_LIMIT ) ) {
			@unlink($filename);
		}
	}
	if (file_exists($filename)==false) {	  
		touch($filename);
		file_put_contents($filename, $sysVersionJson);
	}	
	return true;
} 

//System Information
function pfz_get_system_value($section){
	$filename = "/tmp/sysversion.json";	
	if(file_exists($filename)) {
		$sysVersion = json_decode(file_get_contents($filename), true);
	} else {
		// Install the cron script
		pfz_syscheck_cron_install();
		if($section == "new_version_available") {
			echo "0";
		} else {
			echo "";
		}
	}
	switch ($section){
        case "script_version":
			echo SCRIPT_VERSION;
			break;
		case "version":
            echo( $sysVersion['version']);
            break;
        case "installed_version":
            echo($sysVersion['installed_version']);
            break;
        case "new_version_available":
            if ($sysVersion['version']==$sysVersion['installed_version'])
                echo "0";
            else
                echo "1";
            break;
        case "packages_update":
          	echo $sysVersion["packages_update"];
          	break;
     }
}

//S.M.A.R.T Status
// Taken from /usr/local/www/widgets/widgets/smart_status.widget.php
function pfz_get_smart_status(){

	$devs = get_drive_list();
	$status = 0;
	foreach ($devs as $dev)  { ## for each found drive do                
                $smartdrive_is_displayed = true;
                // This does nothing, only beaks the script when you have an NMVE disk
		//$dev_ident = exec("diskinfo -v /dev/$dev | grep ident   | awk '{print $1}'"); ## get identifier from drive
                $dev_state = trim(exec("smartctl -H /dev/$dev | awk -F: '/^SMART overall-health self-assessment test result/ {print $2;exit}
/^SMART Health Status/ {print $2;exit}'")); ## get SMART state from drive
                switch ($dev_state) {
                        case "PASSED":
                        case "OK":
                                //OK
                                $status=0;                                
                                break;
                        case "":
                                //Unknown
                                $status=2;
                                //return $status;
                                break;
                        default:
                        		//Error
                                $status=1;
                               //return $status;
                                break;
                }
	}
	
	echo $status;
}

function pfz_get_revoked_cert_refs() {
    global $config;    
    $revoked_cert_refs = [];
    foreach ($config["crl"] as $crl) {
        foreach ($crl["cert"] as $revoked_cert) {
            $revoked_cert_refs[] = $revoked_cert["refid"];
        }
    }
	return $revoked_cert_refs;
}

// Certificate discovery
function pfz_cert_discovery(){
    global $config;
    // Contains a list of refs that were revoked and should not be considered
    $revoked_cert_refs = pfz_get_revoked_cert_refs();
	$dataObject = new \stdClass();
	$dataObject->data = [];
    foreach (array("cert", "ca") as $cert_type) {
		foreach ($config[$cert_type] as $i => $cert) {
			if ( ! in_array($cert['refid'], $revoked_cert_refs) ) {
				$certObject = new \stdClass();
				// Trick to keep using only 3 parameters. 
				$certObject->{'{#CERT_INDEX}'} = $cert_type == "cert" ? $i : $i + 0x10000;
				$certObject->{'{#CERT_REFID}'} = $cert['refid'];
				$certObject->{'{#CERT_NAME}'} = $cert['descr'];
				$certObject->{'{#CERT_TYPE}'} = strtoupper($cert_type);
				$dataObject->data[]= $certObject;
			}
		}
	}
	$json_string = json_encode($dataObject);
	echo $json_string;
}

function pfz_get_cert_info($index) {
	// Use a cache file to speed up multiple requests for certificate things. 
	$cacheFile = "/root/.ssl/certinfo_{$index}.json";
	if(file_exists($cacheFile) && (time() - filemtime($cacheFile) < 300)) {
		return json_decode(file_get_contents($cacheFile), true);		
	}
    global $config;    
	if($index >= 0x10000) {
		$index -= 0x10000;
		$certType = "ca";
	} else {
		$certType = "cert";
	}
	$certinfo = openssl_x509_parse(base64_decode($config[$certType][$index]["crt"]));	
	# Don't allow other users access to private keys. 
	if(file_exists($cacheFile)) {
		unlink($cacheFile);
	}
	touch($cacheFile);
	chmod($cacheFile, 0600); 
	if (!is_dir('/root/.ssl')) {
		mkdir('/root/.ssl');
	}
	if(!file_put_contents($cacheFile, json_encode($certinfo))) {
		unlink($cacheFile);
	}	
	return $certinfo;	
}

function pfz_get_cert_pkey_info($index) {
	$details = array();
	
	$cacheFile = "/root/.ssl/certinfo_pk_{$index}.json";
	if(file_exists($cacheFile) && (time() - filemtime($cacheFile) < 300)) {
		return json_decode(file_get_contents($cacheFile), true);		
	}
    global $config;    
	if($index >= 0x10000) {
		$index -= 0x10000;
		$certType = "ca";
	} else {
		$certType = "cert";
	}
	$cert_key = $config[$certType][$index]["crt"];
	if ($cert_key!=false) {
		$publicKey = openssl_pkey_get_public(base64_decode($cert_key));
		$details = openssl_pkey_get_details($publicKey);	
		# Don't allow other users access to private keys. 
		if(file_exists($cacheFile)) {
			unlink($cacheFile);
		}
		touch($cacheFile);
		chmod($cacheFile, 0600); 
		if (!is_dir('/root/.ssl')) {
			mkdir('/root/.ssl');
		}
		if(!file_put_contents($cacheFile, json_encode($details))) {
			unlink($cacheFile);
		}
	}	
	return $details;
}

function pfz_get_ref_cert_algo_len($index){
	$pkInfo = pfz_get_cert_pkey_info($index);
	echo $pkInfo["bits"];
}

# Get the number of bits of security in a cryptographic key. 
function pfz_get_ref_cert_algo_bits($index){
	$pkInfo = pfz_get_cert_pkey_info($index);
	$keyLength = $pkInfo["bits"];
	switch($pkInfo["type"]) {
		case(OPENSSL_KEYTYPE_RSA): 
		case(OPENSSL_KEYTYPE_DSA): 
		case(OPENSSL_KEYTYPE_DH): 
			## See articles on the General Number Field Sieve L-notation complexity.
			$bits = floor( 1 / log(2) * pow(64/9, 1/3) * pow($keyLength * log(2) , 1/3) * pow( log(2048 * log(2)) , 2/3) );
			break;
		case (OPENSSL_KEYTYPE_EC): 
			## Divide by two, floor, via right-shift.
			$bits = $keyLength >> 1;
			break;
	}
	echo $bits;
}

function pfz_get_ref_cert_algo($index){
	$pkInfo = pfz_get_cert_pkey_info($index);
	switch($pkInfo["type"]) {
		case(OPENSSL_KEYTYPE_RSA): 
			echo "RSA";
			break;
		case(OPENSSL_KEYTYPE_DSA): 
			echo "DSA";
			break;
		case(OPENSSL_KEYTYPE_DH): 
			echo "DH";
			break;
		case(OPENSSL_KEYTYPE_EC): 
			echo "EC";
			break;
	}
}

function pfz_get_ref_cert_hash_bits($index){
	// Get the number of bits of security in the hash algorithm.
	$certinfo = pfz_get_cert_info($index);
	$sigType = $certinfo["signatureTypeSN"];
	$upperSigType = strtoupper($sigType);
	if(str_contains($upperSigType, "MD2")) {
		echo 63; 
		return;		
	}
	if(str_contains($upperSigType, "MD4")) {
		echo 2; 
		return;		
	}
	if(str_contains($upperSigType, "MD5")) {
		echo 18;
		return;
	}
	if(str_contains($upperSigType, "SHA1")) {
		echo 61;
		return;		
	}
	if(str_contains($upperSigType, "SHA224")) {
		echo 112;
		return;		
	}
	if(str_contains($upperSigType, "SHA3-224")) {
		echo 112;
		return;		
	}
	if(str_contains($upperSigType, "SHA256")) {
		echo 128;
		return;		
	}
	if(str_contains($upperSigType, "SHA3-256")) {
		echo 128;
		return;		
	}
	if(str_contains($upperSigType, "SHAKE128")) {
		echo 128;
		return;		
	}
	if(str_contains($upperSigType, "SHA384")) {
		echo 192;
		return;		
	}
	if(str_contains($upperSigType, "SHA3-384")) {
		echo 192;
		return;		
	}
	if(str_contains($upperSigType, "SHA512")) {
		echo 256;
		return;		
	}
	if(str_contains($upperSigType, "SHA3-512")) {
		echo 256;
		return;		
	}
	if(str_contains($upperSigType, "SHAKE256")) {
		echo 256;
		return;		
	}
	if(str_contains($upperSigType, "WHIRLPOOL")) {
		echo 256;
		return;		
	}
	if(str_contains($upperSigType, "SHA")) {
		# Assuming 'SHA1' (worst case scenario) for other 'sha' things.
		echo 61;
		return;		
	}
	echo 0;
	return;	
}

function pfz_get_ref_cert_hash($index){
	$certinfo = pfz_get_cert_info($index);
	echo $certinfo["signatureTypeSN"];
}

// Certificate validity for a specific certificate
function pfz_get_ref_cert_date($valuekey, $index){
	$certinfo = pfz_get_cert_info($index);
    switch ($valuekey){
		case "validFrom":
			$value = $certinfo['validFrom_time_t'];
			break;
		case "validTo":
			$value = $certinfo['validTo_time_t'];
			break;
	}
	echo $value;	
}

// Certificats validity date
function pfz_get_cert_date($valuekey){
    global $config;    
    // Contains a list of refs that were revoked and should not be considered
    $revoked_cert_refs = pfz_get_revoked_cert_refs();    
    $value = 0;
        foreach (array("cert", "ca") as $cert_type) {
                switch ($valuekey){
                case "validFrom.max":
                        foreach ($config[$cert_type] as $cert) {
                                if ( ! in_array($cert['refid'], $revoked_cert_refs) ) {
                                        $certinfo = openssl_x509_parse(base64_decode($cert["crt"]));
                                        if ($value == 0 or $value < $certinfo['validFrom_time_t']) $value = $certinfo['validFrom_time_t'];
                                }
            		}
                        break;
                case "validTo.min":
                        foreach ($config[$cert_type] as $cert) {
                                if ( ! in_array($cert['refid'], $revoked_cert_refs) ) {
                                        $certinfo = openssl_x509_parse(base64_decode($cert["crt"]));
                                        if ($value == 0 or $value > $certinfo['validTo_time_t']) $value = $certinfo['validTo_time_t'];
                                }
                        }
                        break;
                }
        }
        echo $value;
}

// File is present
function pfz_file_exists($filename) {
	if (file_exists($filename))
		echo "1";
	else
		echo "0";
}


// Value mappings
// Each value map is represented by an associative array
function pfz_valuemap($valuename, $value, $default="0"){
     switch ($valuename){     

          case "openvpn.server.status":          
                    $valuemap = array(
                         "down" => "0",
                         "up" => "1",
                         "connected (success)" => "1",
                         "none" => "2",
                         "reconnecting; ping-restart" => "3",
                         "waiting" => "4",
                         "server_user_listening" => "5");          
          break;
          
          case "openvpn.client.status":          
                    $valuemap = array(
                         "up" => "1",
                         "connected (success)" => "1",
                         "down" => "0",
                         "none" => "0",
                         "reconnecting; ping-restart" => "2");          
          break;

          case "openvpn.server.mode":
                    $valuemap = array(
                         "p2p_tls" => "1",
                         "p2p_shared_key" => "2",
                         "server_tls" => "3",
                         "server_user" => "4",
                         "server_tls_user" => "5");          
          break;
          
          case "gateway.status":
                    $valuemap = array(
                         "online" => "0",
                         "none" => "0",
                         "loss" => "1",
                         "highdelay" => "2",
                         "highloss" => "3",
                         "force_down" => "4",
                         "down" => "5");          
          break;    
          
          case "ipsec.iketype":
          			$valuemap = array (
          				"auto" => 0,
          				"ikev1" => 1,
          				"ikev2" => 2);
          break;
          
          case "ipsec.mode":
          			$valuemap = array (
          				"main" => 0,
          				"aggressive" => 1);
          break;
          
          case "ipsec.protocol":
          			$valuemap = array (
          				"both" => 0,
          				"inet" => 1,
          				"inet6" => 2);
          break;
          
          case "ipsec_ph2.mode":
          			$valuemap = array (
          				"transport" => 0,
          				"tunnel" => 1,
          				"tunnel6" => 2);
          break;
          
          case "ipsec_ph2.protocol":
          			$valuemap = array (
          				"esp" => 1,
          				"ah" => 2);
          break;

		  case "ipsec.state":
          			$valuemap = array (
          				"established" => 1,
          				"connecting" => 2,
          				"installed" => 1,
          				"rekeyed" => 2);
          break;

     }

     if (is_array($valuemap)) {
     	$value = strtolower($value);
     	if (array_key_exists($value, $valuemap))
          	return $valuemap[$value];
     }
     return $default;
}

/*
 * Contadores de tráfego para gráficos "só cliente" (total − gerência Baitz).
 *
 * Escala frota: exclusão por CIDR/IP (PF states), sem alterar regras do site.
 *
 * Métricas:
 *   total    — bytes da interface
 *   excluded — bytes acumulados de states com src/dst em PFZ_TRAFFIC_EXCLUDE_NETS
 *   clean    — max(0, total − excluded)
 *
 * Uso Zabbix:
 *   pfsense.value[traffic_filtered,{#IFNAME},clean,in]
 *   pfsense.value[traffic_filtered,{#IFNAME},excluded,out]
 */
function pfz_traffic_resolve_hwif($ifname) {
	$ifname = trim((string)$ifname);
	if ($ifname === '') {
		return '';
	}

	$ifaces = get_interface_arr();
	if (is_array($ifaces) && in_array($ifname, $ifaces, true)) {
		return $ifname;
	}

	$ifinfo = get_interface_info($ifname);
	if (is_array($ifinfo) && !empty($ifinfo['hwif'])) {
		return $ifinfo['hwif'];
	}

	return $ifname;
}

function pfz_traffic_if_bytes($ifname) {
	$hwif = pfz_traffic_resolve_hwif($ifname);
	$in = 0;
	$out = 0;

	$ifdescrs = get_configured_interface_with_descr(true);
	if (is_array($ifdescrs)) {
		foreach ($ifdescrs as $ifn => $ifd) {
			$ifinfo = get_interface_info($ifn);
			if (!is_array($ifinfo)) {
				continue;
			}
			if ($ifn === $ifname || (isset($ifinfo['hwif']) && $ifinfo['hwif'] === $hwif)) {
				$in = isset($ifinfo['inbytes']) ? (float)$ifinfo['inbytes'] : 0;
				$out = isset($ifinfo['outbytes']) ? (float)$ifinfo['outbytes'] : 0;
				return array('in' => $in, 'out' => $out, 'hwif' => $hwif);
			}
		}
	}

	$hwif_esc = escapeshellarg($hwif);
	exec("/usr/bin/netstat -I {$hwif_esc} -ibn 2>/dev/null", $lines);
	if (is_array($lines)) {
		foreach ($lines as $line) {
			if (strpos($line, $hwif) === false) {
				continue;
			}
			$parts = preg_split('/\s+/', trim($line));
			if (count($parts) >= 10 && $parts[0] === $hwif && is_numeric($parts[4])) {
				$in = (float)$parts[6];
				$out = (float)$parts[9];
				break;
			}
		}
	}

	return array('in' => $in, 'out' => $out, 'hwif' => $hwif);
}

function pfz_traffic_parse_exclude_nets() {
	static $parsed = null;
	if ($parsed !== null) {
		return $parsed;
	}
	$parsed = array();
	$raw = defined('PFZ_TRAFFIC_EXCLUDE_NETS') ? PFZ_TRAFFIC_EXCLUDE_NETS : '';
	foreach (explode(',', $raw) as $part) {
		$part = trim($part);
		if ($part === '') {
			continue;
		}
		if (strpos($part, '/') === false) {
			$part .= '/32';
		}
		$bits = explode('/', $part, 2);
		$ip = trim($bits[0]);
		$prefix = isset($bits[1]) ? (int)$bits[1] : 32;
		$long = ip2long($ip);
		if ($long === false) {
			continue;
		}
		$long = $long & 0xFFFFFFFF;
		if ($prefix < 0) {
			$prefix = 0;
		}
		if ($prefix > 32) {
			$prefix = 32;
		}
		$mask = ($prefix === 0) ? 0 : (0xFFFFFFFF << (32 - $prefix)) & 0xFFFFFFFF;
		$parsed[] = array(
			'network' => $long & $mask,
			'mask' => $mask,
			'cidr' => $part,
		);
	}
	return $parsed;
}

function pfz_traffic_ip_excluded($ip) {
	$long = ip2long($ip);
	if ($long === false) {
		return false;
	}
	$long = $long & 0xFFFFFFFF;
	foreach (pfz_traffic_parse_exclude_nets() as $net) {
		if (($long & $net['mask']) === $net['network']) {
			return true;
		}
	}
	return false;
}

function pfz_traffic_extract_ipv4($endpoint) {
	// "10.0.0.1:9103" | "10.0.0.1:9103 (host)" | "(10.0.0.1)"
	if (preg_match('/(\d{1,3}(?:\.\d{1,3}){3})/', $endpoint, $m)) {
		return $m[1];
	}
	return '';
}

/*
 * Extrai hwif do primeiro token da linha de state PF.
 * Retorna '' para "all" / sem iface (não atribuir a wan/lan).
 */
function pfz_traffic_parse_state_hwif($line) {
	if (!preg_match('/^(\S+)\s+/', $line, $m)) {
		return '';
	}
	$token = $m[1];
	$proto = array('tcp', 'udp', 'icmp', 'esp', 'ah', 'gre', 'icmp6', 'ipv6-icmp', 'carp', 'pfsync');
	if (in_array(strtolower($token), $proto, true)) {
		return '';
	}
	if (strcasecmp($token, 'all') === 0) {
		return '';
	}
	return $token;
}

/*
 * Snapshot PF states que tocam CIDRs Baitz, agrupados por hwif.
 * dir: dst in exclude => out | src in exclude => in | ambos => out
 * States com prefixo 'all' aguardam origif: <hwif> nas linhas de metadados do pfctl.
 * Isso preserva atribuição por interface sem contaminar WAN/LAN.
 */
function pfz_traffic_cidr_snapshot() {
	$states = array(); // states[hwif][id] = {bytes, dir, src, dst}
	$snap_in = array();
	$snap_out = array();
	$matched = array();
	$samples = array(); // até 5 IPs matched por hwif

	exec('/sbin/pfctl -ss -vv 2>/dev/null', $lines);
	if (!is_array($lines) || count($lines) === 0) {
		return array(
			'states' => $states,
			'snap_in' => $snap_in,
			'snap_out' => $snap_out,
			'matched' => $matched,
			'samples' => $samples,
		);
	}

	$cur_id = '';
	$cur_src = '';
	$cur_dst = '';
	$cur_hwif = '';
	$cur_bytes = 0;
	$have_flow = false;

	$flush = function () use (
		&$states, &$snap_in, &$snap_out, &$matched, &$samples,
		&$cur_id, &$cur_src, &$cur_dst, &$cur_hwif, &$cur_bytes, &$have_flow
	) {
		if (!$have_flow || $cur_id === '' || $cur_hwif === '') {
			$cur_id = $cur_src = $cur_dst = $cur_hwif = '';
			$cur_bytes = 0;
			$have_flow = false;
			return;
		}
		$src_ex = ($cur_src !== '' && pfz_traffic_ip_excluded($cur_src));
		$dst_ex = ($cur_dst !== '' && pfz_traffic_ip_excluded($cur_dst));
		if (!$src_ex && !$dst_ex) {
			$cur_id = $cur_src = $cur_dst = $cur_hwif = '';
			$cur_bytes = 0;
			$have_flow = false;
			return;
		}
		$hwif = $cur_hwif;
		if (!isset($matched[$hwif])) {
			$matched[$hwif] = 0;
			$snap_in[$hwif] = 0;
			$snap_out[$hwif] = 0;
			$states[$hwif] = array();
			$samples[$hwif] = array();
		}
		$matched[$hwif]++;
		if ($dst_ex && !$src_ex) {
			$dir = 'out';
			$snap_out[$hwif] += $cur_bytes;
		} elseif ($src_ex && !$dst_ex) {
			$dir = 'in';
			$snap_in[$hwif] += $cur_bytes;
		} else {
			$dir = 'out';
			$snap_out[$hwif] += $cur_bytes;
		}
		$states[$hwif][$cur_id] = array(
			'bytes' => $cur_bytes,
			'dir' => $dir,
			'src' => $cur_src,
			'dst' => $cur_dst,
		);
		if (count($samples[$hwif]) < 5) {
			$hit = $dst_ex ? $cur_dst : $cur_src;
			if ($hit !== '' && !in_array($hit, $samples[$hwif], true)) {
				$samples[$hwif][] = $hit;
			}
		}
		$cur_id = $cur_src = $cur_dst = $cur_hwif = '';
		$cur_bytes = 0;
		$have_flow = false;
	};

	foreach ($lines as $line) {
		$trim = trim($line);
		if ($trim === '') {
			continue;
		}

		// "vmx0 tcp A:port -> B:port …" | "all tcp A -> B …" | "tcp A -> B …"
		if (preg_match(
			'/^(?:([\w\.\-]+)\s+)?(tcp|udp|icmp|esp|ah|gre|icmp6|ipv6-icmp|carp|pfsync)\s+(\S+)\s*(->|<-)\s*(\S+)/i',
			$trim,
			$fm
		)) {
			$flush();
			$iface_token = isset($fm[1]) ? $fm[1] : '';
			// Em pfSense 2.7/2.8, muitos states aparecem como "all tcp ..." e a
			// interface real vem depois como "origif: vmx0". Não descarte o flow:
			// mantenha-o pendente até processar as linhas de metadados.
			if ($iface_token === '' || strcasecmp($iface_token, 'all') === 0) {
				$cur_hwif = '';
			} else {
				$cur_hwif = $iface_token;
			}
			$a = pfz_traffic_extract_ipv4($fm[3]);
			$b = pfz_traffic_extract_ipv4($fm[5]);
			if ($fm[4] === '<-') {
				$cur_src = $b;
				$cur_dst = $a;
			} else {
				$cur_src = $a;
				$cur_dst = $b;
			}
			$have_flow = true;
			continue;
		}

		if (preg_match('/^(\S+)\s+(?:tcp|udp|icmp|esp|ah|gre)\s+(\S+)\s*(->|<-)\s*(\S+)/i', $trim, $fm)) {
			$flush();
			$cur_hwif = pfz_traffic_parse_state_hwif($trim);
			if ($cur_hwif === '') {
				$have_flow = false;
				continue;
			}
			$a = pfz_traffic_extract_ipv4($fm[2]);
			$b = pfz_traffic_extract_ipv4($fm[4]);
			if ($fm[3] === '<-') {
				$cur_src = $b;
				$cur_dst = $a;
			} else {
				$cur_src = $a;
				$cur_dst = $b;
			}
			$have_flow = true;
			continue;
		}

		if (preg_match('/\b(?:tcp|udp|icmp)\s+from\s+(\S+)\s+to\s+(\S+)/i', $trim, $fm)) {
			$flush();
			// formato sem iface explícito — descartar
			$cur_hwif = '';
			$have_flow = false;
			continue;
		}

		if (!$have_flow) {
			continue;
		}

		// pfctl -ss -vv: a interface original pode vir apenas na linha de metadata.
		if (preg_match('/\borigif:\s*([\w.\-]+)/i', $trim, $om)) {
			$origif = $om[1];
			if ($origif !== '' && strcasecmp($origif, 'all') !== 0) {
				$cur_hwif = $origif;
			}
		}

		// IDs atuais são hexadecimais em pfSense/FreeBSD (ex.: ff87e07200000000).
		if (preg_match('/\bid:\s*([0-9a-f]+)/i', $trim, $im)) {
			$cur_id = strtolower($im[1]);
		}

		// Formatos observados:
		//   1050897283:552185352 bytes
		//   bytes 12345 / bytes: 12345
		// Para o acumulador por state usamos o total bidirecional do state.
		if (preg_match('/\b(\d+):(\d+)\s+bytes\b/i', $trim, $bm)) {
			$cur_bytes = (float)$bm[1] + (float)$bm[2];
		} elseif (preg_match('/\bbytes[:\s]+(\d+)/i', $trim, $bm)) {
			$cur_bytes = (float)$bm[1];
		}
	}
	$flush();

	return array(
		'states' => $states,
		'snap_in' => $snap_in,
		'snap_out' => $snap_out,
		'matched' => $matched,
		'samples' => $samples,
	);
}

function pfz_traffic_load_state_file() {
	$file = PFZ_TRAFFIC_STATE_FILE;
	$empty = array(
		'ifaces' => array(), // hwif => {cumulative_in, cumulative_out, states, matched}
		'updated' => 0,
		'version' => 2,
	);
	if (!file_exists($file)) {
		return $empty;
	}
	$data = json_decode(@file_get_contents($file), true);
	if (!is_array($data)) {
		return $empty;
	}
	// Migração v1 (global) -> v2 (por hwif): descarta acumulador antigo
	if (!isset($data['ifaces']) || !is_array($data['ifaces'])) {
		return $empty;
	}
	return array_merge($empty, $data);
}

function pfz_traffic_save_state_file($data) {
	@file_put_contents(PFZ_TRAFFIC_STATE_FILE, json_encode($data));
}

function pfz_traffic_iface_bucket($store, $hwif) {
	if ($hwif === '') {
		return array(
			'in' => 0,
			'out' => 0,
			'found' => false,
			'matched' => 0,
			'samples' => array(),
			'mode' => 'cidr-states',
		);
	}
	$ifaces = isset($store['ifaces']) && is_array($store['ifaces']) ? $store['ifaces'] : array();
	if (!isset($ifaces[$hwif]) || !is_array($ifaces[$hwif])) {
		return array(
			'in' => 0,
			'out' => 0,
			'found' => false,
			'matched' => 0,
			'samples' => array(),
			'mode' => 'cidr-states',
		);
	}
	$b = $ifaces[$hwif];
	$in = isset($b['cumulative_in']) ? (float)$b['cumulative_in'] : 0;
	$out = isset($b['cumulative_out']) ? (float)$b['cumulative_out'] : 0;
	$matched = isset($b['matched']) ? (int)$b['matched'] : 0;
	$samples = isset($b['samples']) && is_array($b['samples']) ? $b['samples'] : array();
	return array(
		'in' => $in,
		'out' => $out,
		'found' => ($matched > 0) || ($in + $out > 0),
		'matched' => $matched,
		'samples' => $samples,
		'mode' => 'cidr-states',
	);
}

/*
 * Acumula deltas dos states CIDR-matched por hwif -> contador monotônico.
 * Zabbix: change_per_second (+ *8 para bps).
 * Sem alterar regras PF; lista unica em PFZ_TRAFFIC_EXCLUDE_NETS.
 */
function pfz_traffic_excluded_bytes_from_cidr($hwif = '') {
	$now = time();
	$prev = pfz_traffic_load_state_file();

	if (($now - (int)$prev['updated']) < (int)PFZ_TRAFFIC_STATE_CACHE_TTL
		&& (int)$prev['updated'] > 0
	) {
		return pfz_traffic_iface_bucket($prev, $hwif);
	}

	$snap = pfz_traffic_cidr_snapshot();
	$prev_ifaces = isset($prev['ifaces']) && is_array($prev['ifaces']) ? $prev['ifaces'] : array();
	$new_ifaces = array();

	$all_hwifs = array_unique(array_merge(array_keys($prev_ifaces), array_keys($snap['states'])));
	foreach ($all_hwifs as $h) {
		$prev_b = isset($prev_ifaces[$h]) && is_array($prev_ifaces[$h]) ? $prev_ifaces[$h] : array();
		$cum_in = isset($prev_b['cumulative_in']) ? (float)$prev_b['cumulative_in'] : 0;
		$cum_out = isset($prev_b['cumulative_out']) ? (float)$prev_b['cumulative_out'] : 0;
		$prev_states = isset($prev_b['states']) && is_array($prev_b['states']) ? $prev_b['states'] : array();
		$cur_states = isset($snap['states'][$h]) && is_array($snap['states'][$h]) ? $snap['states'][$h] : array();
		$delta_in = 0;
		$delta_out = 0;

		foreach ($cur_states as $id => $st) {
			$bytes = (float)$st['bytes'];
			$dir = $st['dir'];
			$prev_bytes = isset($prev_states[$id]['bytes']) ? (float)$prev_states[$id]['bytes'] : 0;
			$d = $bytes - $prev_bytes;
			if ($d < 0) {
				$d = $bytes;
			}
			if ($d > 0) {
				if ($dir === 'in') {
					$delta_in += $d;
				} else {
					$delta_out += $d;
				}
			}
		}

		$cum_in += $delta_in;
		$cum_out += $delta_out;
		$matched_h = isset($snap['matched'][$h]) ? (int)$snap['matched'][$h] : 0;
		$samples_h = isset($snap['samples'][$h]) && is_array($snap['samples'][$h]) ? $snap['samples'][$h] : array();

		$new_ifaces[$h] = array(
			'cumulative_in' => $cum_in,
			'cumulative_out' => $cum_out,
			'states' => $cur_states,
			'matched' => $matched_h,
			'samples' => $samples_h,
			'last_snap_in' => isset($snap['snap_in'][$h]) ? $snap['snap_in'][$h] : 0,
			'last_snap_out' => isset($snap['snap_out'][$h]) ? $snap['snap_out'][$h] : 0,
			'last_delta_in' => $delta_in,
			'last_delta_out' => $delta_out,
		);
	}

	$save = array(
		'ifaces' => $new_ifaces,
		'updated' => $now,
		'version' => 2,
	);
	pfz_traffic_save_state_file($save);

	return pfz_traffic_iface_bucket($save, $hwif);
}

function pfz_traffic_label_matches($label) {
	$markers = array(PFZ_TRAFFIC_EXCLUDE_LABEL, 'zbx_excl', 'zbx_backup');
	foreach ($markers as $want) {
		$want = trim((string)$want);
		if ($want === '') {
			continue;
		}
		if (stripos($label, $want) !== false) {
			return true;
		}
	}
	return false;
}

function pfz_traffic_bytes_from_labels() {
	$in = 0;
	$out = 0;
	$found = false;
	exec('/sbin/pfctl -vsl 2>/dev/null', $lines);
	if (!is_array($lines)) {
		return array('in' => 0, 'out' => 0, 'found' => false);
	}
	foreach ($lines as $line) {
		$line = trim($line);
		if ($line === '') {
			continue;
		}
		if (!preg_match('/^(.*?)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)(?:\s+(\d+))?$/', $line, $m)) {
			continue;
		}
		if (!pfz_traffic_label_matches(trim($m[1]))) {
			continue;
		}
		$found = true;
		$in += (float)$m[6];
		$out += (float)$m[8];
	}
	return array('in' => $in, 'out' => $out, 'found' => $found);
}

function pfz_traffic_backup_bytes($hwif = '') {
	$cidr = pfz_traffic_excluded_bytes_from_cidr($hwif);
	// Labels PF são globais; não misturar no modo por-iface (pode contaminar WAN/LAN).
	// Mantido só se USE_LABELS=true E hwif vazio (legacy).
	if ($hwif === '' && defined('PFZ_TRAFFIC_USE_LABELS') && PFZ_TRAFFIC_USE_LABELS) {
		$lab = pfz_traffic_bytes_from_labels();
		if (!empty($lab['found'])) {
			$cidr['in'] = max((float)$cidr['in'], (float)$lab['in']);
			$cidr['out'] = max((float)$cidr['out'], (float)$lab['out']);
			$cidr['found'] = true;
			$cidr['mode'] = 'cidr+labels';
		}
	}
	return $cidr;
}

function pfz_traffic_pick_direction($bytes, $direction) {
	$direction = strtolower(trim((string)$direction));
	$in = isset($bytes['in']) ? (float)$bytes['in'] : 0;
	$out = isset($bytes['out']) ? (float)$bytes['out'] : 0;

	switch ($direction) {
		case 'in':
		case 'inbound':
			return $in;
		case 'out':
		case 'outbound':
			return $out;
		case 'both':
		case 'total':
		case 'sum':
			return $in + $out;
		default:
			return $in;
	}
}

function pfz_traffic_filtered($ifname, $metric, $direction = 'in') {
	$metric = strtolower(trim((string)$metric));
	$direction = strtolower(trim((string)$direction));
	if ($direction === '') {
		$direction = 'in';
	}

	$total = pfz_traffic_if_bytes($ifname);
	$hwif = isset($total['hwif']) ? $total['hwif'] : pfz_traffic_resolve_hwif($ifname);
	$excl = pfz_traffic_backup_bytes($hwif);

	$total_v = pfz_traffic_pick_direction($total, $direction);
	$excl_v = pfz_traffic_pick_direction($excl, $direction);

	switch ($metric) {
		case 'total':
			$value = $total_v;
			break;
		case 'backup':
		case 'exclude':
		case 'excluded':
		case 'mgmt':
		case 'management':
			$value = $excl_v;
			break;
		case 'clean':
		case 'filtered':
		case 'wanted':
		case 'client':
			$value = $total_v - $excl_v;
			if ($value < 0) {
				$value = 0;
			}
			break;
		case 'debug':
			echo json_encode(array(
				'if' => $ifname,
				'hwif' => $hwif,
				'direction' => $direction,
				'mode' => isset($excl['mode']) ? $excl['mode'] : 'cidr-states',
				'total_in' => $total['in'],
				'total_out' => $total['out'],
				'excluded_in' => $excl['in'],
				'excluded_out' => $excl['out'],
				'excluded_found' => !empty($excl['found']),
				'matched_states' => isset($excl['matched']) ? $excl['matched'] : 0,
				'matched_samples' => isset($excl['samples']) ? $excl['samples'] : array(),
				'exclude_nets' => PFZ_TRAFFIC_EXCLUDE_NETS,
				'state_file' => PFZ_TRAFFIC_STATE_FILE,
				'script_version' => SCRIPT_VERSION,
			));
			return;
		default:
			$value = 0;
			break;
	}

	echo (string)(int)$value;
}

//Argument parsers for Discovery
function pfz_discovery($section){
     switch (strtolower($section)){ 
          case "certificates":
               pfz_cert_discovery();
               break;    
          case "gw":
               pfz_gw_discovery();
               break;
          case "wan":
          	   pfz_interface_discovery(true);
               break;
          case "openvpn_server":
               pfz_openvpn_serverdiscovery();
               break;
          case "openvpn_server_user":
               pfz_openvpn_server_userdiscovery();
               break;
          case "openvpn_client":
               pfz_openvpn_clientdiscovery();
               break;
          case "services":
               pfz_services_discovery();
               break;
          case "interfaces":
               pfz_interface_discovery();
               break;
          case "ipsec_ph1":
          	   pfz_ipsec_discovery_ph1();
               break;
          case "ipsec_ph2":
          	   pfz_ipsec_discovery_ph2();
               break;
          case "dhcpfailover":
          	   pfz_dhcpfailover_discovery();
               break;
          case "temperature_sensors":
               pfz_temperature_sensors_discovery();
               break;
     }         
}

//Main Code
$mainArgument = strtolower($argv[1]);
if(substr($mainArgument, -4, 4) == "cron") {
	// A longer time limit for cron tasks.
	set_time_limit(CRON_TIME_LIMIT);
} else {
	// Set a timeout to prevent a blocked call from stopping all future calls.
    set_time_limit(DEFAULT_TIME_LIMIT);
}

switch ($mainArgument){     
     case "discovery":
          pfz_discovery($argv[2]);
          break;
     case "gw_value":
          pfz_gw_value($argv[2],$argv[3]);
          break;     
     case "gw_status":
          pfz_gw_rawstatus();
          break;
	 case "if_speedtest_value":
	      pfz_speedtest_cron_install();
	 	  pfz_interface_speedtest_value($argv[2],$argv[3]);
	 	  break;
     case "openvpn_servervalue":
          pfz_openvpn_servervalue($argv[2],$argv[3]);
          break;
     case "openvpn_server_uservalue":
          pfz_openvpn_server_uservalue($argv[2],$argv[3]);
          break;
     case "openvpn_server_uservalue_numeric":
          pfz_openvpn_server_uservalue($argv[2],$argv[3],"0");
          break;
     case "openvpn_clientvalue":
          pfz_openvpn_clientvalue($argv[2],$argv[3]);
          break;
     case "service_value":
          pfz_service_value($argv[2],$argv[3]);
          break;
     case "carp_status":
          pfz_carp_status();
          break;
     case "if_name":
          pfz_get_if_name($argv[2]);
          break;
     case "traffic_filtered":
          // argv: traffic_filtered <ifname> <total|excluded|clean|debug> [in|out|both]
          pfz_traffic_filtered(
               isset($argv[2]) ? $argv[2] : '',
               isset($argv[3]) ? $argv[3] : 'clean',
               isset($argv[4]) ? $argv[4] : 'in'
          );
          break;
     case "syscheck_cron":
          pfz_syscheck_cron_install();
          pfz_syscheck_cron();
          break;
     case "system":
          pfz_get_system_value($argv[2]);
          break;
     case "ipsec_ph1":
          pfz_ipsec_ph1($argv[2],$argv[3]);
          break;
     case "ipsec_ph2":
          pfz_ipsec_ph2($argv[2],$argv[3]);
          break;
     case "dhcp":
     	  pfz_dhcp($argv[2],$argv[3]);
          break;
     case "file_exists":
     	  pfz_file_exists($argv[2]);
     	  break;
     case "speedtest_cron":
     	  pfz_speedtest_cron_install();
     	  pfz_speedtest_cron();
     	  break;
	 case "syscheck_cron":
		   pfz_syscheck_cron_install();
		   pfz_syscheck_cron();
		   break;
     case "cron_cleanup":
     	  pfz_speedtest_cron_install(false);
     	  pfz_syscheck_cron_install(false);
     	  break;
     case "smart_status":
          pfz_get_smart_status();
          break;     
     case "cert_ref_date":
          pfz_get_ref_cert_date($argv[2], $argv[3]);
          break;	  
     case "cert_date":
          pfz_get_cert_date($argv[2]);
          break;   
     case "cert_algo":
          pfz_get_ref_cert_algo($argv[2]);
          break;	
     case "cert_algo_bits":
          pfz_get_ref_cert_algo_len($argv[2]);
          break;	
     case "cert_algo_secbits":
          pfz_get_ref_cert_algo_bits($argv[2]);
          break;	
     case "cert_hash":
          pfz_get_ref_cert_hash($argv[2]);
          break;	
     case "cert_hash_secbits":
          pfz_get_ref_cert_hash_bits($argv[2]);
          break;			  
     case "temperature":
          pfz_get_temperature($argv[2]);
          break;
     default:
          pfz_test();
}
