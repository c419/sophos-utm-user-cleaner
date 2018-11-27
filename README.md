### Sophos UTM user cleaner

This program is used for bulk user deletion in Sophos UTM. Sophos UTM lacks features of unused users provisioning and in the same time it is easy to flood system with hundreds or thousands users and corresponding network definitions. It is designed to be safe - it skips deletion of any users or networks that is used somewhere in UTM configuration. This script is intended to be run on Sophos UTM console with root priviledges.

## Installing
`curl -O https://raw.githubusercontent.com/c419/sophos-utm-user-cleaner/master/suuc.py`
or
scp suuc.py into /root/ on your Sophos UTM


## Usage 


`python suuc.py (--list_all|--list_unused|--examine|--delete) [user_list_file]`

                --list_all 
                    Lists all user objects.
                --list_unused
                    Lists all unused user objects. Unused means than user and corresponding network definition is not used in any UTM config sections(except List of existing users) and is not used in any other object definition.
                --examine
                    Reads list of users from file(one username per line) or from STDIN. Writes usage information for each user to Log file.
                --delete
                    Reads list of users from file(one username per line) or from STDIN. Deletes user and corresponding network object if they are unused in UTM, skips otherwise. Writes information to Log file.
                Log file suuc.log will be created in the same directory.

To remove all unused users with one command you can use: `python suuc.py --list_unused | python suuc.py --delete`

        
