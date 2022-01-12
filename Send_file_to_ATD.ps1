# SFTP / ATD 
# Return the status in ePO Custom Props  
# Steen Pedersen, 2022 - Version 004
#
# ------------------------------------------------------------------------------------------------
$c_SFTP_destination ="IP"
#$c_SFTP_destination ="10.10.10.241"
$c_SFTP_user ="<FileUploadUser>"
$c_SFTP_password ="<Password>"
$c_SFTP_dst_port = "22"
$c_SFTP_dst_folder = "\"

# Used for the MVISION EDR reaction - the sting filename will be replaced with the 
$c_SourceFileName = '{{filename}}'
#$c_SourceFileName="C:\test\reg_new2.exe"

# ------------------------------------------------------------------------------------------------
#
# Preapare some environmental variables
$g_results =''
$g_temp_status_file = $env:temp+'\scriptflow.log'
$g_working_dir = $PSScriptRoot
$g_ISO_Date_with_time = Get-Date -format "yyyy-MM-dd HH:mm:ss"
# ------------------------------------------------------------------------------------------------


# Next function allows to work with self-signed certificates
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    
    public class IDontCarePolicy : ICertificatePolicy {
        public IDontCarePolicy() {}
        public bool CheckValidationResult(
            ServicePoint sPoint, X509Certificate cert,
            WebRequest wRequest, int certProb) {
            return true;
        }
    }
"@


function Submit-Atd
    {
    [CmdletBinding()]
    Param
        (
        # ATD Server related parameters
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string] $Atd_host, 
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string] $Atd_user,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string] $Atd_pass,
        
        # Parameter related to the files that will be uploded to the ATD, Pipe allowed
        [Parameter(ParameterSetName="file", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true, Mandatory=$true)] 
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [String[]] $Fullname  
        )
    Begin
        {

        # Function used during the memorystream building object, used for the multi-part header when submitting files to ATD

        function Get-AsciiBytes([String] $str) 
            {
            return [System.Text.Encoding]::ASCII.GetBytes($str)            
            }
        
        ########## Set of commands related to the connection with ATD server #########

        # Allow self-Signed certificates

        # Note: I have found many references indicating that they way to allow self signed certificates is setting to true the next policy.
        # [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        # However after many tries the only way I have been able to make it work is through the class previusly defined
       
        [System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy 

        # Foring the system to use TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
          
        # The $credentials variable will be used in the authentication header, that information must be sent in B64 format
        $Credentials = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Atd_user+":"+$Atd_pass))

        # Authentication header
        $auth_header = @{
                        'Accept'       = 'application/vnd.ve.v1.0+json'
                        'Content-Type' = 'application/json'
                        'VE-SDK-API'   = $Credentials
                        };

        # Invoking the connection using the powerhsell invoke-restmethod
        $login_url = "https://${Atd_host}/php/session.php"

        try 
            {
            $response = Invoke-RestMethod -Uri $login_url -Method Get -Headers $auth_header
            }
        catch 
            {
            # If something goes wrong we break the script
            # Note: The begin section of this cmdlet is the only place where I break the script, in the Process section I don't break the script as I allow piping
            # Add info to local log
            
            Add-Content $g_temp_status_file "Connection issue to: $login_url"
            
            Write-Error ("Error: Connection with ATD server couldn't be made - $login_url")
            $_.Exception | Format-List -Force
            break
            }
        
        # If the connection successes we get the session value and we build the session header for further communications with the ATD API
        If ($response.success)
            {
            $session  = $response.results.session
            $user_ID  = $response.results.userId
            $matd_Ver = $response.results.matdVersion
            $api_Ver  = $response.results.apiVersion

            $Credentials = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($session+":"+$user_ID))

            $session_header = @{
                                'Accept'       = 'application/vnd.ve.v1.0+json'
                                 'VE-SDK-API'   = $Credentials
                               };

            # As the objective of this script is to upload files to the ATD for analysis I generate the post data in this section.
            # Generating the post data in this section avoids this part of the code to be executed multiple times.
            $post_data = @{
                          'data' = @{
                                    'data' = @{
                                            'xMode'         = '0'
                                            'skipTaskId'    = '1'
                                            'srcIp'         = ''
                                            'destIp'        = ''
                                            'messageId'     = ''
                                            'analyzeAgain'  = '1'
                                            'vmProfileList' = '0'
                                            }
                                    'filePriorityQ' = 'run_now'
                                    }
                          }
            # Later we will need this information in Json instead of a hashtable
            $post_data = $post_data | ConvertTo-Json

            }
        Else
            {
            # If something goes wrong we break the script
            # Note: The begin section of this cmdlet is the only place where I break the script, in the Process section I don't break the script as I allow piping
            Write-Error("Error: Information returned unexpected")
            break
            }

        }
    Process
        {
        $upload_url = "https://${Atd_host}/php/fileupload.php"
        $Report = @()
        foreach($file in $Fullname)
            {
		    $file_name = Split-Path $file -leaf

            # Check that the file passed as a parameter really exits and points to a file
            If (Test-Path -Path $file -PathType Leaf)
                {
                try
                    {
                    # I read the file with two objectives:
                    #  - Calculate the size of the file if it's bigger than 120 MB I avoid sumition
                    #  - If the file is smaller I will need this information during the multi-part header creation process
                    $bin_file = [System.IO.File]::ReadAllBytes($file)
                    }
                catch
                    {
                    # .NET ReadAllBytes function creates an exception if the file to read is bigger than 2 GB, so I capture the exception and I create a flag variable for further use.
                    $too_big = 1
                    }

                If ($bin_file.Length /1024 /1024 -lt 120 -And -Not ($too_big))
                    {
                    # File is smaller than 120 MB, and the 2GB exception has not been generated.
                

            
                    <# 
                    ######################################################################################################################################
                    NOTE: This code allows to get the Content Type of a file.
                      During my tests I have realized that it is not necessary to expecify correctly the Content Type during the file submition to the ATD 
                      as later on ATD will do this for every submition
                      So later on I hardcode the ContentType to application/octet-stream during the muti-part header construction.
                    ######################################################################################################################################
                    Add-Type -AssemblyName System.Web
 
                    $mimeType = [System.Web.MimeMapping]::GetMimeMapping($file)
            
                    if ($mimeType)
                    {
                        $ContentType = $mimeType
                    }
                    else
                    {
                        $ContentType = "application/octet-stream"
                    }
                    #####################################################################################################################################
                    #>
        
            		
                    # Note:
                    #   PowerShell doesn't support mutipart headers in the same way that the python requests module does, so the best way I have found is to
                    #   create a Memory Stream where the multipart header will be written and then send this memory stream in the POST request. 
                    #
                    #   McAfee ATD expects a multi-part header with two sections, the first section includes the name of the file as well as the file info
                    #   the second section includes the post-data created on the begin section of the cmdlet 

                    ############ building Multi-part header ###############

                    [byte[]]$CRLF = 13, 10

                    $body = New-Object System.IO.MemoryStream

                    $boundary = [Guid]::NewGuid().ToString().Replace('-','')
                    $ContentType = 'multipart/form-data; boundary=' + $boundary
                    $b2 = Get-AsciiBytes ('--' + $boundary)
                    $body.Write($b2, 0, $b2.Length)
                    $body.Write($CRLF, 0, $CRLF.Length)
  
                    $b = (Get-AsciiBytes ('Content-Disposition: form-data; name="amas_filename"; filename="' + $file_name + '";'))
                    $body.Write($b, 0, $b.Length)
                    $body.Write($CRLF, 0, $CRLF.Length)            
                    $b = (Get-AsciiBytes 'Content-Type:application/octet-stream')
                    $body.Write($b, 0, $b.Length)

                    $body.Write($CRLF, 0, $CRLF.Length)
                    $body.Write($CRLF, 0, $CRLF.Length)
            
                    #$b = [System.IO.File]::ReadAllBytes($file) --> $bin_file previously created to calculate file size
                    $body.Write($bin_file, 0, $bin_file.Length)

                    $body.Write($CRLF, 0, $CRLF.Length)
                    $body.Write($b2, 0, $b2.Length)
                    $body.Write($CRLF, 0, $CRLF.Length)

                    $b = (Get-AsciiBytes ('Content-Disposition: form-data; name="data"'))
                    $body.Write($b, 0, $b.Length)

                    $body.Write($CRLF, 0, $CRLF.Length)
                    $body.Write($CRLF, 0, $CRLF.Length)
            
                    $b = (Get-AsciiBytes $post_data)
                    $body.Write($b, 0, $b.Length)
        
                    $body.Write($CRLF, 0, $CRLF.Length)
                    $body.Write($b2, 0, $b2.Length)
            
                    $b = (Get-AsciiBytes '--')
                    $body.Write($b, 0, $b.Length)
            
                    $body.Write($CRLF, 0, $CRLF.Length)


                    # Once the header as well as the post information arre created I invoke the invoke-restmethod cmdlet
                    #
                    # In this case, as opposite than during the  begin section, I don't break the script if something goes wrong allowing piping.
                    # I create an object instead, so typical cmdlets transformations can be done.
               

                    try 
                        {
                    $response = Invoke-RestMethod -Uri $upload_url -ContentType $ContentType -Method Post -Headers $session_header -Body $body.ToArray()
                        }
                    catch
                        {
                        Write-Error ("Error: File {$file_name} couldn't be uploaded to ATD server")
                        }

                    If ($response.success)
                        {
                        # I know I should write this in a better way, but anyway it works


                        $atd_submition = new-object psobject -property @{
                                                                  sucess    = $response.success 
                                                                  file_name = $file_name
                                                                  file_size = $response.results.size
                                                                  mimeType  = $response.mimeType
                                                                  md5       = $response.results.md5
                                                                  sha1      = $response.results.sha1
                                                                  sha256    = $response.results.sha256
                                                                  detail    = 'Upload process sucessfull'
                                                                 }
         
                        }
                    Else
                        {
                        $atd_submition = new-object psobject -property @{
                                                                  sucess    = 'False' 
                                                                  file_name = $file_name
                                                                  file_size = ''
                                                                  mimeType  = ''
                                                                  md5       = ''
                                                                  sha1      = ''
                                                                  sha256    = ''
                                                                  detail    = 'Error: Information received by ATD unexpected'
                                                                 }
                        }
                    }
                Else
                    {
                    # File is bigger than 120 MB
                    $atd_submition = new-object psobject -property @{
                                                                  sucess    = 'False' 
                                                                  file_name = $file_name
                                                                  file_size = ''
                                                                  mimeType  = ''
                                                                  md5       = ''
                                                                  sha1      = ''
                                                                  sha256    = ''
                                                                  detail    = 'Error: File bigger than permitted'
                                                                 }

                    }
           
                }
            Else
                {
                $atd_submition = new-object psobject -property @{
                                                              sucess    = 'False' 
                                                              file_name = $file_name
                                                              file_size = ''
                                                              mimeType  = ''
                                                              md5       = ''
                                                              sha1      = ''
                                                              sha256    = ''
                                                              detail    = "Error: File doesn't exist of doesn't point to a file"
                                                             }
                }
            $report += $atd_submition 
            #return $atd_submition
            }
        return $report
    }
    End
        {
        # Close the connection to ATD

        $logout_url = "https://${Atd_host}/php/session.php"
        $response = Invoke-RestMethod -Uri $logout_url -Method Delete -Headers $session_header 

        }
    }


function send-files3()
{
    param(
        [string]$SourceCabinet,
        [string]$DestinationUser,  
        [string]$DestinationIP,
        [string]$DestinationPort,
        [string]$DestinationFolder
    )
    Write-Output "-----Ready to send---------";
    Write-Output "Source file:     $SourceCabinet";
    Write-Output "ATP Destination: $DestinationIP";
    Write-Output "ATP User:        $DestinationUser";

    #$scp_commandline =  @("-P", $DestinationPort, $SourceCabinet, $destination) -join " ";
    #Write-Output "Simulated SCP: Would Have Sent To: $scp_commandline";
    
    #get-content $SourceCabinet | Submit-atd -Atd_host $DestinationIP -Atd_user $DestinationUser -Atd_pass $c_SFTP_password
    Submit-atd -Atd_host $DestinationIP -Atd_user $DestinationUser -Atd_pass $c_SFTP_password -Fullname $SourceCabinet


    Get-Date -format "yyyyMMdd_HHmmss"
    
    #Exitecode 0 = file is upload
    #Exitecode 1 = file is not upload - file do not exits or wrong password
    #if ($process_status.ExitCode -eq 0)
    if (0 -eq 0)
    {
        $Global:g_results = 'File uploaded: '+$SourceCabinet+' to '+$c_SFTP_destination;
    }
    else {
        $Global:g_results = 'Failed to uploaded: '+$SourceCabinet+' to '+$c_SFTP_destination;
        
    }

}


function write_customprops()
    {
           param(
            [string]$Value
        )
    # Find path to McAfee Agent
    # Read information from 64 bit
    if ((Get-WmiObject win32_operatingsystem | Select-Object osarchitecture).osarchitecture -like "64*")
    {
    #64bit code here
    Write-Output "64-bit OS"
    $path_to_agent = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Network Associates\ePolicy Orchestrator\Agent" -Name "Installed Path")."Installed Path"
    $Command_maconfig = $path_to_agent+'\..\MACONFIG.exe'
    $Command_cmdagent = $path_to_agent+'\..\CMDAGENT.exe'
    }
    else
    {
    #32bit code here
    Write-Output "32-bit OS"
    $path_to_agent = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Network Associates\ePolicy Orchestrator\Agent" -Name "Installed Path")."Installed Path"
    $Command_maconfig = $path_to_agent+'\MACONFIG.exe'
    $Command_cmdagent = $path_to_agent+'\CMDAGENT.exe'
    }
     
    $path_to_agent
    #$path_to_agent32 = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Network Associates\ePolicy Orchestrator\Agent" -Name "Installed Path")."Installed Path"
    $Parms = " -custom -prop8 "
    $Parms = $Parms+'"'+$Value+'"'
    #$Parms
    #$Command_maconfig
    #& $Command_maconfig @($Parms)
    try {
        $process_status = Start-Process  $Command_maconfig -ArgumentList $Parms -NoNewWindow -PassThru -Wait        
    }
    catch {
        "Error running $Command_maconfig"
        Add-Content $g_temp_status_file "Error running $Command_maconfig"
    }
    
    # Perform CMDAGENT.EXE -p
    # Collect and Send Props
    #%comspec% /c "%agent_path%\cmdagent.exe" -p
    #& $Command_cmdagent @('-p')
    try {
        $process_status = Start-Process  $Command_cmdagent -ArgumentList '-p' -NoNewWindow -PassThru -Wait
    }
    catch {
        "Error running $Command_cmdagent"
        Add-Content $g_temp_status_file "Error running $Command_cmdagent"
    }
    
    }


################
# Main section #
################
function main()
{
    [CmdletBinding()]
    param( [string]$SourceFileName)
    #for ( $i=0; $i -lt $args.count; $i++){
        #write-host $args[$i]
     #}
    
    # fil name as paramter to be used in EEDK
    #$SourceFileName = $Args
 

    #"Status input"
    #$SourceFileName
    #"End status"
    
    #---test---
    $_scp_file = $c_SourceFileName

    #check_file_exits
    if(Test-path $_scp_file -PathType leaf)
        {
            # if the file exist
            # Chekc the Destination is reachable - currenlty on port 443 this must be changed to chekc the $c_SFTP_dst_port 
            #$l_ATD_access = Test-ServerSSLSupport3 ($c_SFTP_destination)
            #Write-Output "Destination check:     $l_ATD_access";

            #$l_status_access = tnc -Port $c_SFTP_dst_port -ComputerName $c_SFTP_destination 
            Write-Output "Destination check:     "
            $l_status_access.TcpTestSucceeded
            #if ($l_ATD_access.TLSv1_2 -eq $true) 
            #if ($l_status_access.TcpTestSucceeded -eq $true) 
            if ($True -eq $true) 
            {
                "Access to Destination"
                Add-Content $g_temp_status_file "Ready to upload file "
                Add-Content $g_temp_status_file "-SourceCabinet $_scp_file -DestinationUser $c_SFTP_user -DestinationIP $c_SFTP_destination -DestinationPort $c_SFTP_dst_port  -DestinationFolder $c_SFTP_dst_folder"
                send-files3 -SourceCabinet $_scp_file -DestinationUser $c_SFTP_user -DestinationIP $c_SFTP_destination -DestinationPort $c_SFTP_dst_port  -DestinationFolder $c_SFTP_dst_folder;
            }
            else {
                $Global:g_results = "Destination not reachable "+$c_SFTP_destination+" Port "+$c_SFTP_dst_port                
            }
        }
        else
        {
            # if file do not exists
            $Global:g_results = "File not found "+$_scp_file 
        }



    $Global:g_results = $Global:g_results +", AT: "+$g_ISO_Date_with_time
    write_customprops($Global:g_results)
    
    "Status added to "+$g_temp_status_file
    Add-Content $g_temp_status_file "$Global:g_results"

    'Results: '+$Global:g_results
    
    #"Completed : "
    #Get-Date -format "yyyyMMdd_HHmmss"
    
}

main
