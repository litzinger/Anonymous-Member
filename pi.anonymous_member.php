<?php

/*
=====================================================
 Authur: Brian Litzinger
-----------------------------------------------------
 http://boldminded.com/
=====================================================
 This program is freeware; 
 you may use this code for any purpose, commercial or
 private, without any further permission from the author.
=====================================================
 File: pi.anonymous_member.php
-----------------------------------------------------
 Purpose:   Create an anonymous user to be able to fake 
            a user in the session. Username and password 
            are encrypted, and user can't login. 
            Originally intended to accompany Solspace's 
            Favorites module, so site visitors can 
            create Favorites without registering
            a member account.
=====================================================
*/

$plugin_info = array(
    'pi_name'           => 'Anonymous Member',
    'pi_version'        => '2.0',
    'pi_author'         => 'Brian Litzinger',
    'pi_author_url'     => 'http://boldminded.com/',
    'pi_description'    => 'Create an anonymous member.',
    'pi_usage'          => Anonymous_member::usage()
);


class Anonymous_member {
    
    var $EE;
    var $ip;
    
    function __construct()
    {
        $this->EE =& get_instance();
        $this->ip = $this->EE->input->ip_address();
    }
    
    function create()
    {
        // required
        $group_id = $this->EE->TMPL->fetch_param('group_id');
        
        // optional
        $expires = $this->EE->TMPL->fetch_param('expires', 365);
        $remove_on_expire = $this->EE->TMPL->fetch_param('remove_on_expire');
        $salt = $this->EE->TMPL->fetch_param('salt', '');
        $screen_name = $this->EE->TMPL->fetch_param('screen_name', 'Anonymous Member');
        $screen_name = $screen_name == 'ip' ? $this->ip : $screen_name;
        
        $query = $this->EE->db->get_where('member_groups', array('group_id' => $group_id));
        
        if($query->num_rows() == 0)
        {
            return $this->EE->output->show_user_error('general', array('The Member Group you have defined does not exist.'));
        }
        
        if( ! $group_id)
        {
            return $this->EE->output->show_user_error('general', array('Please define a group to assign the anonymous member to.'));
        }
        
        $member_id = $this->EE->session->userdata['member_id'];
        
        $expire = 60*60*24*$expires;

        // Clean up all old anonymous members from the DB after set expiration date.
        if($remove_on_expire == 'y')
        {
            $diff = $this->EE->localize->now - $expire;
            $this->EE->db->query('DELETE FROM exp_members WHERE join_date <= '. $diff .' AND group_id = '.$group_id);
        }

        if( ! $member_id)
        {
            $data['username']    = 'anonymous_'.$this->EE->functions->random('encrypt');
            $data['password']    = $this->EE->functions->hash($salt.$this->ip);
            $data['ip_address']  = $this->ip;
            $data['unique_id']   = $this->EE->functions->random('encrypt');
            $data['join_date']   = $this->EE->localize->now;
            $data['email']       = '';
            $data['screen_name'] = $screen_name;
            $data['group_id']    = $group_id;
            $data['accept_messages'] = 'n';
            $data['accept_admin_email'] = 'n';  
            $data['accept_user_email'] = 'n';
            $data['notify_by_default'] = 'n';
            $data['notify_of_pm'] = 'n';
            $data['display_avatars'] = 'n';
            $data['display_signatures']  = 'n';
            $data['smart_notifications'] = 'n';
        
            $this->EE->db->insert('members', $data);
            $member_id = $this->EE->db->insert_id();
        
            /** ----------------------------------------
            /**  Following taken directly from EE Member's module. 
            /**  Why re-write this when it already exists?
            /** ----------------------------------------*/
        
            /** ----------------------------------------
            /**  Log user in
            /** ----------------------------------------*/

            $this->EE->functions->set_cookie($this->EE->session->c_expire , time()+$expire, $expire);
            $this->EE->functions->set_cookie($this->EE->session->c_uniqueid , $data['unique_id'], $expire);       
            $this->EE->functions->set_cookie($this->EE->session->c_password , $data['password'],  $expire);   
            $this->EE->functions->set_cookie($this->EE->session->c_anon , 1,  $expire);

            /** ----------------------------------------
            /**  Create a new session
            /** ----------------------------------------*/

            if ($this->EE->config->item('user_session_type') == 'cs' || $this->EE->config->item('user_session_type') == 's')
            {  
                $this->EE->session->sdata['session_id'] = $this->EE->functions->random();  
                $this->EE->session->sdata['member_id']  = $member_id;  
                $this->EE->session->sdata['last_activity'] = $this->EE->localize->now;
                $this->EE->session->sdata['site_id'] = $this->EE->config->item('site_id');

                $this->EE->functions->set_cookie($this->EE->session->c_session , $this->EE->session->sdata['session_id'], $this->EE->session->session_length);   

                $this->EE->db->insert('sessions', $this->EE->session->sdata);
            }

            /** ----------------------------------------
            /**  Update existing session variables
            /** ----------------------------------------*/

            $this->EE->session->userdata['username']  = $data['username'];
            $this->EE->session->userdata['member_id'] = $member_id;
        }
        else
        {
            $this->login();
        }
    }

    function login()
    {
        $member_id = $this->EE->session->userdata['member_id'];

        if( ! $member_id && isset($this->EE->session->userdata['session_id']) && $this->EE->session->userdata['session_id'] != 0 )
        {
            $expire = $expire = 60*60*24*365;
        
            $result = $DB->query("SELECT exp_members.screen_name, 
                                            exp_members.group_id, 
                                            exp_members.username, 
                                            exp_members.member_id, 
                                            exp_members.password, 
                                            exp_members.unique_id
                                    FROM    exp_sessions, exp_members 
                                    WHERE   exp_sessions.session_id  = '". $this->EE->db->escape_str($this->EE->session->userdata['session_id']) ."'
                                    AND     exp_sessions.member_id = exp_members.member_id
                                    AND     exp_sessions.last_activity > $expire");                 

            /** ----------------------------------------
            /**  Set cookies
            /** ----------------------------------------*/
            
            $row = $result->row();
        
            $this->EE->functions->set_cookie($this->EE->session->c_expire , time() + $expire, $expire);
            $this->EE->functions->set_cookie($this->EE->session->c_uniqueid , $row->unique_id, $expire);       
            $this->EE->functions->set_cookie($this->EE->session->c_password , $row->password,  $expire);  
            $this->EE->functions->set_cookie($this->EE->session->c_anon , 1,  $expire);
        
        
            /** ----------------------------------------
            /**  Create a new session
            /** ----------------------------------------*/
        
            $this->EE->session->create_new_session($row->member_id);
            $this->EE->session->userdata['username']  = $row->username;
            $this->EE->session->userdata['member_id'] = $row->member_id;
            $this->EE->session->userdata['screen_name'] = $row->screen_name;
        }
    }
    /* END */
    
    function usage()
    {
        ob_start(); 
        ?>
        
        This plugin lets you create an anonymous member, and immediately signs them in as that member so they can take 
        advantage of certain functionality without registering with the site, which can be a barrier for user interaction.
        
        This was originally written to be used with Solspace's Favorites module.
        
        Require Parameters:
        
        • group_id - Which member group do you want to assign the member to? Would be best to create a new group with no privileges.</li>
        
        Optional Parameters:
        
        • salt - If you want to salt the passwords.
        • screen_name - Screen Name you want to give anonymous users. If screen_name="ip", their IP address will be used instead. Default value is "Anonymous User".
        • expires - Set the number of days you want the anonymous users' cookie to expire.
        • remove_on_expire - If set to "y", whenever a new user is created, all existing users who's join date is older than the expires date will be removed from the database. This is a good way to keep your database clean if you have a heavily trafficked site using this plugin for very temporary purposes, which it is intended for.
        
        Example: {exp:anonymous_member:create group_id="6" salt="mysecret" screen_name="Freeloader"}
        
        To use with the Favorites module, simply include this tag on the page before the "save" method:
        
        {exp:anonymous_member:create group_id="6"}
        {exp:favorites:save}
        
        

        <?php
        $buffer = ob_get_contents();

        ob_end_clean(); 

        return $buffer;
    }
}
?>